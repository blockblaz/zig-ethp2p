//! Ethereum Node Record (ENR) per EIP-778 / RFC 8966.
//!
//! An ENR is an RLP list: `[signature, seq, k, v, k, v, ...]`
//! Keys are byte strings sorted lexicographically; values are RLP-encoded.
//! The record is signed over `[seq, k, v, ...]` (no signature field) using
//! the identity scheme indicated by the `id` key.
//!
//! This module handles RLP encoding/decoding and the record structure.
//! Cryptographic verification is delegated to `discv5/crypto.zig`.

const std = @import("std");

pub const EnrError = error{
    /// RLP item is malformed or truncated.
    BadRlp,
    /// Record exceeds the 300-byte limit (EIP-778 §4).
    RecordTooLarge,
    /// Sequence number must increase on every update.
    StaleSequence,
    /// Required key is absent from the record.
    MissingKey,
    /// Unsupported identity scheme.
    UnknownIdentity,
};

/// Maximum serialised ENR size (EIP-778 §4).
pub const max_record_bytes: usize = 300;

/// Sequence number type — unsigned 64-bit, monotonically increasing.
pub const Seq = u64;

/// A decoded ENR with its raw bytes retained for signature verification.
pub const Enr = struct {
    seq: Seq,
    /// Key-value pairs in wire order (keys are sorted lexicographically).
    pairs: []KvPair,
    /// Signature bytes (scheme-specific length and format).
    signature: []const u8,
    /// The full RLP-encoded record bytes (including signature).
    raw: []const u8,

    allocator: std.mem.Allocator,

    pub fn deinit(self: *Enr) void {
        for (self.pairs) |*kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value_raw);
        }
        self.allocator.free(self.pairs);
        self.allocator.free(self.signature);
        self.allocator.free(self.raw);
        self.* = undefined;
    }

    /// Retrieve the raw (RLP-encoded) value for `key`, or null if absent.
    pub fn get(self: *const Enr, key: []const u8) ?[]const u8 {
        for (self.pairs) |kv| {
            if (std.mem.eql(u8, kv.key, key)) return kv.value_raw;
        }
        return null;
    }
};

pub const KvPair = struct {
    key: []u8,
    /// Raw RLP value bytes (caller decodes as needed).
    value_raw: []u8,
};

// ---------------------------------------------------------------------------
// Minimal RLP codec (subset needed for ENR)
// ---------------------------------------------------------------------------

/// Decode the leading RLP item from `buf`, return it and the remaining bytes.
pub fn rlpDecode(buf: []const u8) EnrError!struct { item: []const u8, rest: []const u8 } {
    if (buf.len == 0) return error.BadRlp;
    const first = buf[0];

    if (first < 0x80) {
        // Single byte.
        return .{ .item = buf[0..1], .rest = buf[1..] };
    }

    if (first < 0xb8) {
        // Short string (0-55 bytes).
        const len: usize = first - 0x80;
        if (buf.len < 1 + len) return error.BadRlp;
        return .{ .item = buf[1 .. 1 + len], .rest = buf[1 + len ..] };
    }

    if (first < 0xc0) {
        // Long string.
        const len_bytes: usize = first - 0xb7;
        if (buf.len < 1 + len_bytes) return error.BadRlp;
        const len = rlpReadBigEndian(buf[1 .. 1 + len_bytes]) catch return error.BadRlp;
        if (buf.len < 1 + len_bytes + len) return error.BadRlp;
        return .{ .item = buf[1 + len_bytes .. 1 + len_bytes + len], .rest = buf[1 + len_bytes + len ..] };
    }

    if (first < 0xf8) {
        // Short list — return entire list payload including prefix.
        const len: usize = first - 0xc0;
        if (buf.len < 1 + len) return error.BadRlp;
        return .{ .item = buf[0 .. 1 + len], .rest = buf[1 + len ..] };
    }

    // Long list.
    const len_bytes: usize = first - 0xf7;
    if (buf.len < 1 + len_bytes) return error.BadRlp;
    const len = rlpReadBigEndian(buf[1 .. 1 + len_bytes]) catch return error.BadRlp;
    if (buf.len < 1 + len_bytes + len) return error.BadRlp;
    return .{ .item = buf[0 .. 1 + len_bytes + len], .rest = buf[1 + len_bytes + len ..] };
}

/// Decode the payload bytes of an RLP list (strips the list prefix).
pub fn rlpListPayload(buf: []const u8) EnrError![]const u8 {
    if (buf.len == 0) return error.BadRlp;
    const first = buf[0];
    if (first < 0xc0) return error.BadRlp;

    if (first < 0xf8) {
        const len: usize = first - 0xc0;
        if (buf.len < 1 + len) return error.BadRlp;
        return buf[1 .. 1 + len];
    }

    const len_bytes: usize = first - 0xf7;
    if (buf.len < 1 + len_bytes) return error.BadRlp;
    const len = rlpReadBigEndian(buf[1 .. 1 + len_bytes]) catch return error.BadRlp;
    if (buf.len < 1 + len_bytes + len) return error.BadRlp;
    return buf[1 + len_bytes .. 1 + len_bytes + len];
}

/// Strip the RLP string prefix and return the raw bytes of the string value.
pub fn rlpStringValue(item: []const u8) EnrError![]const u8 {
    if (item.len == 0) return error.BadRlp;
    const first = item[0];
    if (first < 0x80) return item[0..1];
    if (first < 0xb8) {
        const len: usize = first - 0x80;
        if (item.len < 1 + len) return error.BadRlp;
        return item[1 .. 1 + len];
    }
    if (first < 0xc0) {
        const len_bytes: usize = first - 0xb7;
        if (item.len < 1 + len_bytes) return error.BadRlp;
        const len = rlpReadBigEndian(item[1 .. 1 + len_bytes]) catch return error.BadRlp;
        if (item.len < 1 + len_bytes + len) return error.BadRlp;
        return item[1 + len_bytes .. 1 + len_bytes + len];
    }
    return error.BadRlp;
}

fn rlpReadBigEndian(bytes: []const u8) !usize {
    if (bytes.len == 0 or bytes.len > @sizeOf(usize)) return error.BadRlp;
    var v: usize = 0;
    for (bytes) |b| v = (v << 8) | b;
    return v;
}

/// Encode a byte string as RLP.
pub fn rlpEncodeString(allocator: std.mem.Allocator, data: []const u8) std.mem.Allocator.Error![]u8 {
    if (data.len == 1 and data[0] < 0x80) {
        const out = try allocator.alloc(u8, 1);
        out[0] = data[0];
        return out;
    }
    if (data.len <= 55) {
        const out = try allocator.alloc(u8, 1 + data.len);
        out[0] = @intCast(0x80 + data.len);
        @memcpy(out[1..], data);
        return out;
    }
    const len_bytes = bigEndianLen(data.len);
    const out = try allocator.alloc(u8, 1 + len_bytes + data.len);
    out[0] = @intCast(0xb7 + len_bytes);
    writeBigEndian(out[1 .. 1 + len_bytes], data.len);
    @memcpy(out[1 + len_bytes ..], data);
    return out;
}

fn bigEndianLen(v: usize) usize {
    var n: usize = 1;
    var x = v >> 8;
    while (x > 0) : (x >>= 8) n += 1;
    return n;
}

fn writeBigEndian(out: []u8, v: usize) void {
    var i: usize = out.len;
    var x = v;
    while (i > 0) {
        i -= 1;
        out[i] = @truncate(x & 0xff);
        x >>= 8;
    }
}

// ---------------------------------------------------------------------------
// ENR decode
// ---------------------------------------------------------------------------

/// Decode a complete ENR from its wire encoding (RLP list).
/// The caller owns the returned `Enr` and must call `deinit`.
pub fn decode(allocator: std.mem.Allocator, raw: []const u8) (EnrError || std.mem.Allocator.Error)!Enr {
    if (raw.len > max_record_bytes) return error.RecordTooLarge;

    const raw_owned = try allocator.dupe(u8, raw);
    errdefer allocator.free(raw_owned);

    const payload = try rlpListPayload(raw_owned);
    var rest = payload;

    // First item: signature.
    const sig_item = try rlpDecode(rest);
    const sig_value = try rlpStringValue(sig_item.item);
    const sig_owned = try allocator.dupe(u8, sig_value);
    errdefer allocator.free(sig_owned);
    rest = sig_item.rest;

    // Second item: seq.
    const seq_item = try rlpDecode(rest);
    const seq_bytes = try rlpStringValue(seq_item.item);
    rest = seq_item.rest;
    var seq: Seq = 0;
    for (seq_bytes) |b| seq = (seq << 8) | b;

    // Remaining items: key-value pairs.
    var pairs = std.ArrayListUnmanaged(KvPair){};
    errdefer {
        for (pairs.items) |*kv| {
            allocator.free(kv.key);
            allocator.free(kv.value_raw);
        }
        pairs.deinit(allocator);
    }

    while (rest.len > 0) {
        const k_item = try rlpDecode(rest);
        const k_bytes = try rlpStringValue(k_item.item);
        rest = k_item.rest;

        if (rest.len == 0) return error.BadRlp;
        const v_item = try rlpDecode(rest);
        rest = v_item.rest;

        const key_owned = try allocator.dupe(u8, k_bytes);
        errdefer allocator.free(key_owned);
        const val_owned = try allocator.dupe(u8, v_item.item);

        try pairs.append(allocator, .{ .key = key_owned, .value_raw = val_owned });
    }

    return .{
        .seq = seq,
        .pairs = try pairs.toOwnedSlice(allocator),
        .signature = sig_owned,
        .raw = raw_owned,
        .allocator = allocator,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "rlpEncodeString roundtrip short" {
    const gpa = std.testing.allocator;
    const enc = try rlpEncodeString(gpa, "hello");
    defer gpa.free(enc);
    const val = try rlpStringValue(enc);
    try std.testing.expectEqualStrings("hello", val);
}

test "rlpEncodeString single byte below 0x80" {
    const gpa = std.testing.allocator;
    const enc = try rlpEncodeString(gpa, &.{0x42});
    defer gpa.free(enc);
    try std.testing.expectEqual(@as(usize, 1), enc.len);
    try std.testing.expectEqual(@as(u8, 0x42), enc[0]);
}

test "rlpListPayload strips list prefix" {
    // Manually craft an RLP list containing one short string "ab".
    const list = &[_]u8{ 0xc3, 0x82, 'a', 'b' }; // list(2+1=3), string("ab")
    const payload = try rlpListPayload(list);
    try std.testing.expectEqual(@as(usize, 3), payload.len);
}
