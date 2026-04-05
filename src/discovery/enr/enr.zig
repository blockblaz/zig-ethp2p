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
const crypto = @import("../discv5/crypto.zig");

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
    /// Signature verification failed.
    BadSignature,
    /// Memory allocation failed.
    OutOfMemory,
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

/// Decode the leading RLP item from `buf`, return the **full** item (including
/// its length prefix) and the remaining bytes.
///
/// This is consistent across all types — strings, lists, and single bytes all
/// include the prefix in `item`.  Pass `item` directly to `rlpStringValue` or
/// `rlpListPayload` to strip the prefix and get the payload.
pub fn rlpDecode(buf: []const u8) EnrError!struct { item: []const u8, rest: []const u8 } {
    if (buf.len == 0) return error.BadRlp;
    const first = buf[0];

    if (first < 0x80) {
        // Single byte — the byte itself is both prefix and content.
        return .{ .item = buf[0..1], .rest = buf[1..] };
    }

    if (first < 0xb8) {
        // Short string (0–55 bytes) — include the 0x80-range prefix byte.
        const len: usize = first - 0x80;
        if (buf.len < 1 + len) return error.BadRlp;
        return .{ .item = buf[0 .. 1 + len], .rest = buf[1 + len ..] };
    }

    if (first < 0xc0) {
        // Long string — include prefix + length bytes.
        const len_bytes: usize = first - 0xb7;
        if (buf.len < 1 + len_bytes) return error.BadRlp;
        const len = rlpReadBigEndian(buf[1 .. 1 + len_bytes]) catch return error.BadRlp;
        if (buf.len < 1 + len_bytes + len) return error.BadRlp;
        return .{ .item = buf[0 .. 1 + len_bytes + len], .rest = buf[1 + len_bytes + len ..] };
    }

    if (first < 0xf8) {
        // Short list — include the 0xc0-range prefix byte.
        const len: usize = first - 0xc0;
        if (buf.len < 1 + len) return error.BadRlp;
        return .{ .item = buf[0 .. 1 + len], .rest = buf[1 + len ..] };
    }

    // Long list — include prefix + length bytes.
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
// RLP integer encoding (variable-length big-endian, no leading zeros)
// ---------------------------------------------------------------------------

/// Encode a u64 as an RLP integer (0x80 for zero, or big-endian bytes).
pub fn rlpEncodeUint64(allocator: std.mem.Allocator, v: u64) std.mem.Allocator.Error![]u8 {
    if (v == 0) {
        const out = try allocator.alloc(u8, 1);
        out[0] = 0x80; // RLP empty string = zero integer
        return out;
    }
    // Minimal big-endian bytes.
    var buf: [8]u8 = undefined;
    var len: usize = 0;
    var x = v;
    while (x > 0) : (x >>= 8) {
        buf[7 - len] = @truncate(x & 0xff);
        len += 1;
    }
    const bytes = buf[8 - len ..];
    return rlpEncodeString(allocator, bytes);
}

/// Wrap a slice of pre-encoded RLP items in an RLP list prefix.
pub fn rlpEncodeList(allocator: std.mem.Allocator, items: []const []const u8) std.mem.Allocator.Error![]u8 {
    var payload_len: usize = 0;
    for (items) |it| payload_len += it.len;

    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);

    if (payload_len <= 55) {
        try out.append(allocator, @intCast(0xc0 + payload_len));
    } else {
        const len_bytes = bigEndianLen(payload_len);
        try out.append(allocator, @intCast(0xf7 + len_bytes));
        var tmp: [8]u8 = undefined;
        writeBigEndian(tmp[8 - len_bytes ..], payload_len);
        try out.appendSlice(allocator, tmp[8 - len_bytes ..]);
    }
    for (items) |it| try out.appendSlice(allocator, it);
    return out.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// ENR encode + sign  (EIP-778 §4, v4 identity scheme)
// ---------------------------------------------------------------------------

/// Builder for assembling a signed ENR.
///
/// Pairs must be added in lexicographic key order (the caller is responsible
/// for ordering). Call `sign()` to produce the final wire-encoded record.
pub const EnrBuilder = struct {
    allocator: std.mem.Allocator,
    seq: Seq,
    pairs: std.ArrayListUnmanaged(KvPair) = .{},

    pub fn init(allocator: std.mem.Allocator, seq: Seq) EnrBuilder {
        return .{ .allocator = allocator, .seq = seq };
    }

    pub fn deinit(self: *EnrBuilder) void {
        for (self.pairs.items) |*kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value_raw);
        }
        self.pairs.deinit(self.allocator);
    }

    /// Add a key-value pair. `key` is the plain string; `value_raw` is
    /// already RLP-encoded (e.g. from `rlpEncodeString`).
    pub fn addRaw(
        self: *EnrBuilder,
        key: []const u8,
        value_raw: []const u8,
    ) std.mem.Allocator.Error!void {
        const k = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(k);
        const v = try self.allocator.dupe(u8, value_raw);
        try self.pairs.append(self.allocator, .{ .key = k, .value_raw = v });
    }

    /// Build the RLP content (without the signature) for signing.
    /// Returns allocated bytes; caller must free.
    pub fn buildContent(self: *const EnrBuilder) std.mem.Allocator.Error![]u8 {
        var items = std.ArrayListUnmanaged([]u8){};
        defer {
            for (items.items) |it| self.allocator.free(it);
            items.deinit(self.allocator);
        }

        try items.append(self.allocator, try rlpEncodeUint64(self.allocator, self.seq));
        for (self.pairs.items) |kv| {
            try items.append(self.allocator, try rlpEncodeString(self.allocator, kv.key));
            try items.append(self.allocator, try self.allocator.dupe(u8, kv.value_raw));
        }
        return rlpEncodeList(self.allocator, @ptrCast(items.items));
    }

    /// Sign the record and return the complete RLP-encoded ENR wire bytes.
    /// The result includes: [signature, seq, k, v, ...].
    /// Returns error.RecordTooLarge if the encoded size exceeds 300 bytes.
    pub fn sign(
        self: *const EnrBuilder,
        privkey: [crypto.privkey_len]u8,
    ) (std.mem.Allocator.Error || EnrError || crypto.Secp256k1Error)![]u8 {
        const content = try self.buildContent();
        defer self.allocator.free(content);

        var sig: [crypto.ecdsa_sig_len]u8 = undefined;
        try crypto.ecdsaSign(&sig, content, privkey);

        var items = std.ArrayListUnmanaged([]u8){};
        defer {
            for (items.items) |it| self.allocator.free(it);
            items.deinit(self.allocator);
        }

        try items.append(self.allocator, try rlpEncodeString(self.allocator, &sig));
        try items.append(self.allocator, try rlpEncodeUint64(self.allocator, self.seq));
        for (self.pairs.items) |kv| {
            try items.append(self.allocator, try rlpEncodeString(self.allocator, kv.key));
            try items.append(self.allocator, try self.allocator.dupe(u8, kv.value_raw));
        }

        const record = try rlpEncodeList(self.allocator, @ptrCast(items.items));
        if (record.len > max_record_bytes) {
            self.allocator.free(record);
            return error.RecordTooLarge;
        }
        return record;
    }
};

// ---------------------------------------------------------------------------
// ENR signature verification  (v4 identity scheme)
// ---------------------------------------------------------------------------

/// Verify the v4 identity signature of a decoded ENR.
/// `pubkey` is the 33-byte compressed secp256k1 key from the "secp256k1" field.
pub fn verifyV4(enr: *const Enr, pubkey: [crypto.pubkey_len]u8) (EnrError || crypto.Secp256k1Error)!void {
    if (enr.signature.len != crypto.ecdsa_sig_len) return error.BadSignature;

    // Rebuild the content RLP (seq + kv pairs, no signature).
    var builder = EnrBuilder.init(enr.allocator, enr.seq);
    defer builder.deinit();
    for (enr.pairs) |kv| {
        try builder.addRaw(kv.key, kv.value_raw);
    }
    const content = builder.buildContent() catch return error.OutOfMemory;
    defer enr.allocator.free(content);

    const sig_bytes: [crypto.ecdsa_sig_len]u8 = enr.signature[0..crypto.ecdsa_sig_len].*;
    try crypto.ecdsaVerify(sig_bytes, content, pubkey);
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

test "rlpEncodeUint64 roundtrip" {
    const gpa = std.testing.allocator;
    const cases = [_]u64{ 0, 1, 127, 128, 255, 256, 0xffffffff };
    for (cases) |v| {
        const enc = try rlpEncodeUint64(gpa, v);
        defer gpa.free(enc);
        const item = try rlpDecode(enc);
        const bytes = try rlpStringValue(item.item);
        var decoded: u64 = 0;
        for (bytes) |b| decoded = (decoded << 8) | b;
        try std.testing.expectEqual(v, decoded);
    }
}

test "ENR sign and verify roundtrip" {
    const gpa = std.testing.allocator;

    var privkey: [crypto.privkey_len]u8 = undefined;
    var pubkey: [crypto.pubkey_len]u8 = undefined;
    try crypto.generateEphemeralKeypair(&privkey, &pubkey);

    var builder = EnrBuilder.init(gpa, 1);
    defer builder.deinit();

    const id_val = try rlpEncodeString(gpa, "v4");
    defer gpa.free(id_val);
    try builder.addRaw("id", id_val);

    const pk_val = try rlpEncodeString(gpa, &pubkey);
    defer gpa.free(pk_val);
    try builder.addRaw("secp256k1", pk_val);

    const wire = try builder.sign(privkey);
    defer gpa.free(wire);

    var enr_rec = try decode(gpa, wire);
    defer enr_rec.deinit();

    try verifyV4(&enr_rec, pubkey);
}
