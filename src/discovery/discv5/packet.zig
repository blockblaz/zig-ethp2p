//! discv5 packet codec (discv5 spec §9).
//!
//! Every discv5 UDP datagram begins with a 32-byte `masking-iv` followed by
//! a masked header. Two packet types are defined here:
//!
//!   Ordinary  — carries an encrypted message for an established session.
//!   WHOAREYOU — challenge sent when no session exists for the src node.
//!
//! Only the wire-format types and length constants are implemented here.
//! Full encode/decode requires secp256k1 (see crypto.zig TODOs).

const std = @import("std");
const crypto = @import("crypto.zig");

// ---------------------------------------------------------------------------
// Wire constants (discv5 spec §9)
// ---------------------------------------------------------------------------

/// Random bytes prepended to every datagram; used for AES-CTR masking.
pub const masking_iv_len: usize = 16;

/// Fixed tag value that identifies WHOAREYOU packets (after unmasking).
pub const whoareyou_magic: [6]u8 = .{ 'W', 'H', 'O', 'A', 'R', 'E' };

/// Protocol version field value.
pub const protocol_version: u16 = 0x0001;

/// Static header size for Ordinary packets (protocol-id + version + flag + nonce + auth-size).
pub const ordinary_static_header_len: usize = 6 + 2 + 1 + 12 + 2;

/// Static header size for WHOAREYOU packets.
pub const whoareyou_static_header_len: usize = 6 + 2 + 1 + 12 + 2;

/// Flag byte values.
pub const flag_ordinary: u8 = 0;
pub const flag_whoareyou: u8 = 1;
pub const flag_handshake: u8 = 2;

// ---------------------------------------------------------------------------
// Packet header types
// ---------------------------------------------------------------------------

/// Header fields common to all packet types.
pub const PacketHeader = struct {
    /// 6-byte protocol ID string (`"discv5"`).
    protocol_id: [6]u8,
    version: u16,
    flag: u8,
    /// 12-byte request/response nonce.
    nonce: [12]u8,
    /// Length of the auth-data section that follows this fixed header.
    auth_data_size: u16,
};

/// Auth-data for an Ordinary packet (flag=0): source NodeId.
pub const OrdinaryAuthData = struct {
    src_id: [32]u8,
};

/// Auth-data for a WHOAREYOU packet (flag=1).
pub const WhoareyouAuthData = struct {
    /// id-nonce: 16 random bytes used in key derivation.
    id_nonce: [16]u8,
    /// ENR sequence number of the last-known record for the initiator (0 = unknown).
    enr_seq: u64,
};

/// Auth-data for a Handshake packet (flag=2).
pub const HandshakeAuthData = struct {
    src_id: [32]u8,
    /// Ephemeral secp256k1 public key (33 bytes compressed).
    ephem_pubkey: [33]u8,
    /// Signature over the id-nonce challenge.
    id_sig: [64]u8,
    /// Optional updated ENR (absent = 0 bytes).
    record: []const u8,
};

// ---------------------------------------------------------------------------
// Decoded packet (union)
// ---------------------------------------------------------------------------

pub const PacketKind = union(enum) {
    ordinary: struct {
        header: PacketHeader,
        auth: OrdinaryAuthData,
        /// Encrypted message body (caller decrypts using session key).
        encrypted_body: []const u8,
    },
    whoareyou: struct {
        header: PacketHeader,
        auth: WhoareyouAuthData,
    },
    handshake: struct {
        header: PacketHeader,
        auth: HandshakeAuthData,
        encrypted_body: []const u8,
    },
};

// ---------------------------------------------------------------------------
// Masking key derivation (discv5 spec §9.1)
// ---------------------------------------------------------------------------

/// Derive the 16-byte AES-CTR masking key:
///   masking_key = SHA256(dest_id[0..16] || masking_iv)[0..16]
pub fn maskingKey(dest_id: [32]u8, masking_iv: [masking_iv_len]u8) [16]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(dest_id[0..16]);
    h.update(&masking_iv);
    const digest = h.finalResult();
    return digest[0..16].*;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "maskingKey is deterministic" {
    const dest_id = [_]u8{0xab} ** 32;
    const iv = [_]u8{0x12} ** masking_iv_len;
    const k1 = maskingKey(dest_id, iv);
    const k2 = maskingKey(dest_id, iv);
    try std.testing.expectEqual(k1, k2);
}

test "maskingKey changes with different iv" {
    const dest_id = [_]u8{0xab} ** 32;
    const iv1 = [_]u8{0x12} ** masking_iv_len;
    const iv2 = [_]u8{0x34} ** masking_iv_len;
    const k1 = maskingKey(dest_id, iv1);
    const k2 = maskingKey(dest_id, iv2);
    try std.testing.expect(!std.mem.eql(u8, &k1, &k2));
}

test "flag constants are distinct" {
    try std.testing.expect(flag_ordinary != flag_whoareyou);
    try std.testing.expect(flag_whoareyou != flag_handshake);
}
