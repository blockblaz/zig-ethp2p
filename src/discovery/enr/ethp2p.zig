//! ethp2p ENR extension fields.
//!
//! The `eth-ec` key advertises the node's ethp2p broadcast capabilities so
//! that duty-aware peer selection can filter on EC scheme support without
//! dialling a peer first.
//!
//! Field layout (RLP string, 4 bytes):
//!   byte 0: protocol version
//!   bytes 1-2: EC scheme bitmask (big-endian u16)
//!   byte 3: coarse geographic region hint

const std = @import("std");
const enr = @import("enr.zig");
const ec_scheme = @import("../../layer/ec_scheme.zig");

// ---------------------------------------------------------------------------
// Key strings
// ---------------------------------------------------------------------------

/// ENR key for ethp2p broadcast capability advertisement.
pub const key_eth_ec: []const u8 = "eth-ec";

/// ENR key for DAS custody column bitmap (PeerDAS, future).
pub const key_custody_cols: []const u8 = "custody";

// ---------------------------------------------------------------------------
// Protocol version
// ---------------------------------------------------------------------------

/// Current ethp2p wire protocol version.
/// Bump when a breaking change is made to the broadcast wire format.
pub const protocol_version: u8 = 1;

// ---------------------------------------------------------------------------
// EC scheme bitmask
// ---------------------------------------------------------------------------

/// Bitmask positions for EC schemes, aligned with `EcSchemeKind`.
pub const scheme_bit_reed_solomon: u16 = 1 << 0;
pub const scheme_bit_rlnc: u16 = 1 << 1;

/// Bitmask for all schemes currently implemented end-to-end.
pub const schemes_implemented: u16 = scheme_bit_reed_solomon;

// ---------------------------------------------------------------------------
// Geographic region hint
// ---------------------------------------------------------------------------

/// Coarse continental region codes (not for routing, for diversity enforcement).
pub const GeoRegion = enum(u8) {
    unknown = 0,
    north_america = 1,
    europe = 2,
    asia_pacific = 3,
    south_america = 4,
    africa = 5,
    middle_east = 6,
};

// ---------------------------------------------------------------------------
// eth-ec field
// ---------------------------------------------------------------------------

pub const EthEcField = struct {
    version: u8 = protocol_version,
    schemes: u16 = schemes_implemented,
    geo_region: GeoRegion = .unknown,

    /// Encode to a 4-byte payload (to be RLP-encoded as an ENR value).
    pub fn encode(self: EthEcField) [4]u8 {
        return .{
            self.version,
            @intCast((self.schemes >> 8) & 0xff),
            @intCast(self.schemes & 0xff),
            @intFromEnum(self.geo_region),
        };
    }

    /// Decode from a 4-byte payload (the raw bytes after RLP string decode).
    pub fn decode(bytes: []const u8) enr.EnrError!EthEcField {
        if (bytes.len != 4) return error.BadRlp;
        const schemes = (@as(u16, bytes[1]) << 8) | bytes[2];
        return .{
            .version = bytes[0],
            .schemes = schemes,
            .geo_region = @enumFromInt(bytes[3]),
        };
    }

    /// Whether this peer supports a given EC scheme.
    pub fn supportsScheme(self: EthEcField, kind: ec_scheme.EcSchemeKind) bool {
        const bit: u16 = switch (kind) {
            .reed_solomon => scheme_bit_reed_solomon,
            .rlnc => scheme_bit_rlnc,
        };
        return (self.schemes & bit) != 0;
    }
};

/// Extract and decode the `eth-ec` field from a decoded ENR, or null if absent.
pub fn decodeEthEc(record: *const enr.Enr) enr.EnrError!?EthEcField {
    const raw = record.get(key_eth_ec) orelse return null;
    const val = try enr.rlpStringValue(raw);
    return try EthEcField.decode(val);
}

// ---------------------------------------------------------------------------
// DAS custody column bitmap (future PeerDAS)
// ---------------------------------------------------------------------------

pub const CustodyCols = u64;
pub const custody_cols_all: CustodyCols = std.math.maxInt(u64);

pub fn decodeCustodyCols(record: *const enr.Enr) enr.EnrError!?CustodyCols {
    const raw = record.get(key_custody_cols) orelse return null;
    const val = try enr.rlpStringValue(raw);
    if (val.len > 8) return error.BadRlp;
    var v: u64 = 0;
    for (val) |b| v = (v << 8) | b;
    return v;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "EthEcField encode/decode roundtrip" {
    const f = EthEcField{
        .version = 1,
        .schemes = scheme_bit_reed_solomon | scheme_bit_rlnc,
        .geo_region = .europe,
    };
    const enc = f.encode();
    const dec = try EthEcField.decode(&enc);
    try std.testing.expectEqual(f.version, dec.version);
    try std.testing.expectEqual(f.schemes, dec.schemes);
    try std.testing.expectEqual(f.geo_region, dec.geo_region);
}

test "supportsScheme checks correct bit" {
    const f = EthEcField{ .schemes = scheme_bit_reed_solomon };
    try std.testing.expect(f.supportsScheme(.reed_solomon));
    try std.testing.expect(!f.supportsScheme(.rlnc));
}

test "schemes_implemented includes reed_solomon only" {
    try std.testing.expect((schemes_implemented & scheme_bit_reed_solomon) != 0);
    try std.testing.expect((schemes_implemented & scheme_bit_rlnc) == 0);
}
