//! Standard ENR key names and field decoders (EIP-778, devp2p ENR spec).

const std = @import("std");
const enr = @import("enr.zig");

// ---------------------------------------------------------------------------
// Standard field key strings
// ---------------------------------------------------------------------------

pub const key_id: []const u8 = "id";
pub const key_secp256k1: []const u8 = "secp256k1";
pub const key_ip: []const u8 = "ip";
pub const key_ip6: []const u8 = "ip6";
pub const key_tcp: []const u8 = "tcp";
pub const key_tcp6: []const u8 = "tcp6";
pub const key_udp: []const u8 = "udp";
pub const key_udp6: []const u8 = "udp6";

/// Only supported identity scheme for ethp2p (secp256k1 per EIP-778).
pub const identity_v4: []const u8 = "v4";

/// Compressed secp256k1 public key (33 bytes).
pub const Secp256k1Pubkey = [33]u8;

/// Node ID derived from a secp256k1 pubkey: `keccak256(uncompressed_pubkey[1..])`.
/// The full 32-byte value is used for Kademlia distance calculations.
pub const NodeId = [32]u8;

pub const StandardFields = struct {
    /// Compressed secp256k1 public key (33 bytes); null if missing.
    pubkey: ?Secp256k1Pubkey = null,
    /// IPv4 address; null if missing.
    ip: ?std.net.Ip4Address = null,
    /// IPv6 address; null if missing.
    ip6: ?std.net.Ip6Address = null,
    /// TCP port (host byte order); 0 if missing.
    tcp: u16 = 0,
    /// UDP port (host byte order); 0 if missing.
    udp: u16 = 0,
};

/// Decode standard fields from a decoded ENR.
pub fn decodeStandard(record: *const enr.Enr) enr.EnrError!StandardFields {
    var out = StandardFields{};

    if (record.get(key_secp256k1)) |raw| {
        const val = try enr.rlpStringValue(raw);
        if (val.len != 33) return error.BadRlp;
        out.pubkey = val[0..33].*;
    }

    if (record.get(key_ip)) |raw| {
        const val = try enr.rlpStringValue(raw);
        if (val.len != 4) return error.BadRlp;
        out.ip = std.net.Ip4Address.init(val[0..4].*, 0);
    }

    if (record.get(key_udp)) |raw| {
        const val = try enr.rlpStringValue(raw);
        if (val.len != 2) return error.BadRlp;
        out.udp = std.mem.readInt(u16, val[0..2], .big);
    }

    if (record.get(key_tcp)) |raw| {
        const val = try enr.rlpStringValue(raw);
        if (val.len != 2) return error.BadRlp;
        out.tcp = std.mem.readInt(u16, val[0..2], .big);
    }

    return out;
}

test "decodeStandard parses udp port" {
    // Build a minimal ENR with a udp field manually.
    const gpa = std.testing.allocator;

    // RLP-encode port 30303 (0x765f) as 2-byte big-endian string.
    const port_raw = &[_]u8{ 0x82, 0x76, 0x5f };
    const port_key = try enr.rlpEncodeString(gpa, "udp");
    defer gpa.free(port_key);

    // Minimal ENR (no signature check here, just field decode path).
    var pairs = [_]enr.KvPair{.{
        .key = @constCast("udp"),
        .value_raw = @constCast(port_raw),
    }};
    const record = enr.Enr{
        .seq = 1,
        .pairs = &pairs,
        .signature = &.{},
        .raw = &.{},
        .allocator = gpa,
    };

    const std_fields = try decodeStandard(&record);
    try std.testing.expectEqual(@as(u16, 0x765f), std_fields.udp);
}
