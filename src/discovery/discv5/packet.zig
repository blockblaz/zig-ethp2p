//! discv5 packet codec (discv5 spec §9).
//!
//! Every discv5 UDP datagram is laid out as:
//!
//!   masking_iv(16) || masked_header || message
//!
//! The header is AES-128-CTR encrypted with a key derived from the
//! destination NodeId and the masking IV. This hides the protocol-id
//! "discv5" from passive observers.
//!
//! Three packet types:
//!   Ordinary   (flag=0) — encrypted message for an established session.
//!   WHOAREYOU  (flag=1) — challenge sent when no session exists.
//!   Handshake  (flag=2) — completes the cryptographic handshake.

const std = @import("std");
const crypto = @import("crypto.zig");

// ---------------------------------------------------------------------------
// Wire constants (discv5 spec §9)
// ---------------------------------------------------------------------------

/// Random bytes prepended to every datagram; used for AES-CTR masking.
pub const masking_iv_len: usize = 16;

/// 6-byte ASCII protocol identifier written into every header.
pub const protocol_id = "discv5";

/// Protocol version field.
pub const protocol_version: u16 = 0x0001;

/// Maximum datagram size we will ever send or accept.
pub const max_datagram_len: usize = 1280;

/// Static header size (protocol_id + version + flag + nonce + auth_data_size).
pub const static_header_len: usize = 6 + 2 + 1 + 12 + 2;

/// Flag byte values.
pub const flag_ordinary: u8 = 0;
pub const flag_whoareyou: u8 = 1;
pub const flag_handshake: u8 = 2;

/// Auth-data size for ORDINARY packets: just src-id (32 bytes).
pub const ordinary_auth_size: u16 = 32;

/// Auth-data size for WHOAREYOU packets: id-nonce(16) + enr-seq(8).
pub const whoareyou_auth_size: u16 = 24;

// ---------------------------------------------------------------------------
// Packet header types
// ---------------------------------------------------------------------------

pub const PacketHeader = struct {
    flag: u8,
    /// 12-byte request/response nonce.
    nonce: [12]u8,
    /// Length of the auth-data section that follows this fixed header.
    auth_data_size: u16,
};

pub const OrdinaryAuthData = struct {
    src_id: [32]u8,
};

pub const WhoareyouAuthData = struct {
    /// 16 random bytes used in key derivation.
    id_nonce: [16]u8,
    /// ENR sequence number of the last-known record (0 = unknown).
    enr_seq: u64,
};

/// Auth-data for a Handshake packet (flag=2).
pub const HandshakeAuthData = struct {
    src_id: [32]u8,
    /// Ephemeral secp256k1 public key (33 bytes compressed).
    ephem_pubkey: [33]u8,
    /// ECDSA id-signature (64 bytes compact).
    id_sig: [64]u8,
    /// Optional updated ENR bytes (length 0 = not included).
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
// AES-128-CTR masking  (discv5 spec §9.1)
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

/// AES-128-CTR XOR keystream.  Used for both masking and unmasking
/// (CTR mode is symmetric).
pub fn aes128CtrXor(key: [16]u8, iv: [16]u8, in: []const u8, out: []u8) void {
    std.debug.assert(in.len == out.len);
    const Aes128 = std.crypto.core.aes.Aes128;
    var ctx = Aes128.initEnc(key);
    var counter: [16]u8 = iv;
    var offset: usize = 0;

    while (offset < in.len) {
        var block: [16]u8 = undefined;
        ctx.encrypt(&block, &counter);

        const chunk = @min(16, in.len - offset);
        for (0..chunk) |i| out[offset + i] = in[offset + i] ^ block[i];
        offset += chunk;

        // Increment counter (big-endian).
        var j: usize = 15;
        while (true) {
            counter[j] +%= 1;
            if (counter[j] != 0) break;
            if (j == 0) break;
            j -= 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Packet encode
// ---------------------------------------------------------------------------

pub const EncodeError = error{ BufferTooSmall, RecordTooLarge };

/// Encode an ORDINARY packet into `out`.
/// Returns the number of bytes written.
///
/// Wire layout:
///   masking_iv(16) || masked( protocol_id(6) | version(2) | flag(1) |
///                              nonce(12) | auth_size(2) | src_id(32) ) ||
///   encrypted_body
pub fn encodeOrdinary(
    out: []u8,
    masking_iv: [masking_iv_len]u8,
    dest_id: [32]u8,
    nonce: [12]u8,
    src_id: [32]u8,
    encrypted_body: []const u8,
) EncodeError!usize {
    const header_plain_len = static_header_len + ordinary_auth_size;
    const total = masking_iv_len + header_plain_len + encrypted_body.len;
    if (out.len < total) return error.BufferTooSmall;

    // Write masking_iv.
    @memcpy(out[0..masking_iv_len], &masking_iv);

    // Build plaintext header.
    var hdr: [static_header_len + ordinary_auth_size]u8 = undefined;
    @memcpy(hdr[0..6], protocol_id);
    std.mem.writeInt(u16, hdr[6..8], protocol_version, .big);
    hdr[8] = flag_ordinary;
    @memcpy(hdr[9..21], &nonce);
    std.mem.writeInt(u16, hdr[21..23], ordinary_auth_size, .big);
    @memcpy(hdr[23..55], &src_id);

    // Mask the header.
    const key = maskingKey(dest_id, masking_iv);
    aes128CtrXor(key, masking_iv, &hdr, out[masking_iv_len .. masking_iv_len + header_plain_len]);

    // Append the (already-encrypted) message body unchanged.
    @memcpy(out[masking_iv_len + header_plain_len ..][0..encrypted_body.len], encrypted_body);

    return total;
}

/// Encode a WHOAREYOU packet into `out`.
pub fn encodeWhoareyou(
    out: []u8,
    masking_iv: [masking_iv_len]u8,
    dest_id: [32]u8,
    nonce: [12]u8,
    id_nonce: [16]u8,
    enr_seq: u64,
) EncodeError!usize {
    const header_plain_len = static_header_len + whoareyou_auth_size;
    const total = masking_iv_len + header_plain_len;
    if (out.len < total) return error.BufferTooSmall;

    @memcpy(out[0..masking_iv_len], &masking_iv);

    var hdr: [static_header_len + whoareyou_auth_size]u8 = undefined;
    @memcpy(hdr[0..6], protocol_id);
    std.mem.writeInt(u16, hdr[6..8], protocol_version, .big);
    hdr[8] = flag_whoareyou;
    @memcpy(hdr[9..21], &nonce);
    std.mem.writeInt(u16, hdr[21..23], whoareyou_auth_size, .big);
    @memcpy(hdr[23..39], &id_nonce);
    std.mem.writeInt(u64, hdr[39..47], enr_seq, .big);

    const key = maskingKey(dest_id, masking_iv);
    aes128CtrXor(key, masking_iv, &hdr, out[masking_iv_len .. masking_iv_len + header_plain_len]);

    return total;
}

/// Encode a HANDSHAKE packet into `out`.
/// `record` may be empty (len=0) if no ENR update is included.
pub fn encodeHandshake(
    out: []u8,
    masking_iv: [masking_iv_len]u8,
    dest_id: [32]u8,
    nonce: [12]u8,
    auth: HandshakeAuthData,
    encrypted_body: []const u8,
) EncodeError!usize {
    if (auth.record.len > 300) return error.RecordTooLarge;

    // auth-data = src_id(32) + sig_size(1) + eph_key_size(1) + record_size(2)
    //           + id_sig(64) + eph_pubkey(33) + record(record_size)
    const auth_size: u16 = @intCast(32 + 1 + 1 + 2 + 64 + 33 + auth.record.len);
    const header_plain_len = static_header_len + auth_size;
    const total = masking_iv_len + header_plain_len + encrypted_body.len;
    if (out.len < total) return error.BufferTooSmall;

    @memcpy(out[0..masking_iv_len], &masking_iv);

    var hdr_buf: [static_header_len + 32 + 1 + 1 + 2 + 64 + 33 + 300]u8 = undefined;
    var pos: usize = 0;
    @memcpy(hdr_buf[0..6], protocol_id);
    pos = 6;
    std.mem.writeInt(u16, hdr_buf[pos..][0..2], protocol_version, .big);
    pos += 2;
    hdr_buf[pos] = flag_handshake;
    pos += 1;
    @memcpy(hdr_buf[pos..][0..12], &nonce);
    pos += 12;
    std.mem.writeInt(u16, hdr_buf[pos..][0..2], auth_size, .big);
    pos += 2;
    @memcpy(hdr_buf[pos..][0..32], &auth.src_id);
    pos += 32;
    hdr_buf[pos] = 64; // sig_size
    pos += 1;
    hdr_buf[pos] = 33; // eph_key_size
    pos += 1;
    std.mem.writeInt(u16, hdr_buf[pos..][0..2], @intCast(auth.record.len), .big);
    pos += 2;
    @memcpy(hdr_buf[pos..][0..64], &auth.id_sig);
    pos += 64;
    @memcpy(hdr_buf[pos..][0..33], &auth.ephem_pubkey);
    pos += 33;
    @memcpy(hdr_buf[pos..][0..auth.record.len], auth.record);
    pos += auth.record.len;

    const key = maskingKey(dest_id, masking_iv);
    aes128CtrXor(key, masking_iv, hdr_buf[0..pos], out[masking_iv_len .. masking_iv_len + pos]);
    if (encrypted_body.len > 0) {
        @memcpy(out[masking_iv_len + pos ..][0..encrypted_body.len], encrypted_body);
    }

    return total;
}

// ---------------------------------------------------------------------------
// Packet decode
// ---------------------------------------------------------------------------

pub const DecodeError = error{
    TooShort,
    BadProtocolId,
    BadVersion,
    UnknownFlag,
    BadAuthSize,
    BufferTooSmall,
};

/// Decode a received UDP datagram into a `PacketKind`.
/// `local_id` is our NodeId (used to derive the masking key).
///
/// AES-128-CTR is a stream cipher: the entire masked header region MUST be
/// unmasked in a single pass.  Splitting into two calls would restart the
/// keystream and corrupt bytes beyond the first block boundary.
///
/// The returned `PacketKind` contains slices into `datagram` and `hdr_buf`,
/// both of which must outlive the returned value.
pub fn decode(
    datagram: []const u8,
    local_id: [32]u8,
    hdr_buf: *[static_header_len + 300 + 32]u8,
) DecodeError!PacketKind {
    if (datagram.len < masking_iv_len + static_header_len) return error.TooShort;

    const masking_iv = datagram[0..masking_iv_len].*;
    const key = maskingKey(local_id, masking_iv);
    const masked_region = datagram[masking_iv_len..];

    // Unmask as much of the header region as fits in hdr_buf in ONE CTR pass.
    // This is critical: splitting the unmask into multiple calls restarts the
    // keystream counter and corrupts data after the first 16-byte block.
    const unmask_len = @min(masked_region.len, hdr_buf.len);
    aes128CtrXor(key, masking_iv, masked_region[0..unmask_len], hdr_buf[0..unmask_len]);

    const hdr = hdr_buf[0..static_header_len];

    if (!std.mem.eql(u8, hdr[0..6], protocol_id)) return error.BadProtocolId;
    if (std.mem.readInt(u16, hdr[6..8], .big) != protocol_version) return error.BadVersion;

    const flag = hdr[8];
    const nonce: [12]u8 = hdr[9..21].*;
    const auth_data_size = std.mem.readInt(u16, hdr[21..23], .big);

    const needed = masking_iv_len + static_header_len + auth_data_size;
    if (datagram.len < needed) return error.TooShort;
    if (static_header_len + auth_data_size > hdr_buf.len) return error.BufferTooSmall;

    const auth_data = hdr_buf[static_header_len .. static_header_len + auth_data_size];

    const hdr_struct = PacketHeader{
        .flag = flag,
        .nonce = nonce,
        .auth_data_size = auth_data_size,
    };

    switch (flag) {
        flag_ordinary => {
            if (auth_data_size != ordinary_auth_size) return error.BadAuthSize;
            const src_id: [32]u8 = auth_data[0..32].*;
            return .{ .ordinary = .{
                .header = hdr_struct,
                .auth = .{ .src_id = src_id },
                .encrypted_body = datagram[needed..],
            } };
        },

        flag_whoareyou => {
            if (auth_data_size != whoareyou_auth_size) return error.BadAuthSize;
            const id_nonce: [16]u8 = auth_data[0..16].*;
            const enr_seq = std.mem.readInt(u64, auth_data[16..24], .big);
            return .{ .whoareyou = .{
                .header = hdr_struct,
                .auth = .{ .id_nonce = id_nonce, .enr_seq = enr_seq },
            } };
        },

        flag_handshake => {
            // auth-data: src_id(32) + sig_size(1) + eph_key_size(1) +
            //            record_size(2) + id_sig(sig_size) + eph_pubkey(eph_key_size) + record
            if (auth_data_size < 32 + 1 + 1 + 2) return error.BadAuthSize;
            const src_id: [32]u8 = auth_data[0..32].*;
            const sig_size: usize = auth_data[32];
            const eph_key_size: usize = auth_data[33];
            const record_size: usize = std.mem.readInt(u16, auth_data[34..36], .big);
            const min_auth = 32 + 1 + 1 + 2 + sig_size + eph_key_size + record_size;
            if (auth_data_size < min_auth or sig_size != 64 or eph_key_size != 33)
                return error.BadAuthSize;

            var id_sig: [64]u8 = undefined;
            @memcpy(&id_sig, auth_data[36..100]);
            var ephem_pubkey: [33]u8 = undefined;
            @memcpy(&ephem_pubkey, auth_data[100..133]);
            const record = auth_data[133 .. 133 + record_size];

            return .{ .handshake = .{
                .header = hdr_struct,
                .auth = .{
                    .src_id = src_id,
                    .ephem_pubkey = ephem_pubkey,
                    .id_sig = id_sig,
                    .record = record,
                },
                .encrypted_body = datagram[needed..],
            } };
        },

        else => return error.UnknownFlag,
    }
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
    try std.testing.expect(!std.mem.eql(u8, &maskingKey(dest_id, iv1), &maskingKey(dest_id, iv2)));
}

test "aes128CtrXor is its own inverse" {
    const key = [_]u8{0x42} ** 16;
    const iv = [_]u8{0x11} ** 16;
    const plain = "hello masking!xy"; // exactly 16 bytes
    var ct: [plain.len]u8 = undefined;
    var pt: [plain.len]u8 = undefined;
    aes128CtrXor(key, iv, plain, &ct);
    aes128CtrXor(key, iv, &ct, &pt);
    try std.testing.expectEqualStrings(plain, &pt);
}

test "ORDINARY packet encode/decode roundtrip" {
    const dest_id = [_]u8{0xDD} ** 32;
    const src_id = [_]u8{0xCC} ** 32;
    const nonce = [_]u8{0x11} ** 12;
    const masking_iv = [_]u8{0x55} ** masking_iv_len;
    const body = "encrypted-body";

    var buf: [1280]u8 = undefined;
    const n = try encodeOrdinary(&buf, masking_iv, dest_id, nonce, src_id, body);

    var hdr_buf: [static_header_len + 300 + 32]u8 = undefined;
    const pkt = try decode(buf[0..n], dest_id, &hdr_buf);

    try std.testing.expectEqual(flag_ordinary, pkt.ordinary.header.flag);
    try std.testing.expectEqual(nonce, pkt.ordinary.header.nonce);
    try std.testing.expectEqualSlices(u8, &src_id, &pkt.ordinary.auth.src_id);
    try std.testing.expectEqualSlices(u8, body, pkt.ordinary.encrypted_body);
}

test "WHOAREYOU packet encode/decode roundtrip" {
    const dest_id = [_]u8{0xDD} ** 32;
    const nonce = [_]u8{0x22} ** 12;
    const masking_iv = [_]u8{0x66} ** masking_iv_len;
    const id_nonce = [_]u8{0xAA} ** 16;
    const enr_seq: u64 = 42;

    var buf: [1280]u8 = undefined;
    const n = try encodeWhoareyou(&buf, masking_iv, dest_id, nonce, id_nonce, enr_seq);

    var hdr_buf: [static_header_len + 300 + 32]u8 = undefined;
    const pkt = try decode(buf[0..n], dest_id, &hdr_buf);

    try std.testing.expectEqual(flag_whoareyou, pkt.whoareyou.header.flag);
    try std.testing.expectEqual(id_nonce, pkt.whoareyou.auth.id_nonce);
    try std.testing.expectEqual(enr_seq, pkt.whoareyou.auth.enr_seq);
}

test "HANDSHAKE packet encode/decode roundtrip" {
    const dest_id = [_]u8{0xDD} ** 32;
    const nonce = [_]u8{0x33} ** 12;
    const masking_iv = [_]u8{0x77} ** masking_iv_len;
    const auth = HandshakeAuthData{
        .src_id = [_]u8{0x01} ** 32,
        .ephem_pubkey = [_]u8{0x02} ++ [_]u8{0xBB} ** 32,
        .id_sig = [_]u8{0xFF} ** 64,
        .record = &[_]u8{},
    };
    const body = "handshake-body";

    var buf: [1280]u8 = undefined;
    const n = try encodeHandshake(&buf, masking_iv, dest_id, nonce, auth, body);

    var hdr_buf: [static_header_len + 300 + 32]u8 = undefined;
    const pkt = try decode(buf[0..n], dest_id, &hdr_buf);

    try std.testing.expectEqual(flag_handshake, pkt.handshake.header.flag);
    try std.testing.expectEqualSlices(u8, &auth.src_id, &pkt.handshake.auth.src_id);
    try std.testing.expectEqualSlices(u8, &auth.ephem_pubkey, &pkt.handshake.auth.ephem_pubkey);
    try std.testing.expectEqualSlices(u8, body, pkt.handshake.encrypted_body);
}

test "flag constants are distinct" {
    try std.testing.expect(flag_ordinary != flag_whoareyou);
    try std.testing.expect(flag_whoareyou != flag_handshake);
}
