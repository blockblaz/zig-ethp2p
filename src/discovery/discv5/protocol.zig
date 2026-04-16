//! discv5 message types (discv5 spec §10).
//!
//! Messages are RLP-encoded, then encrypted with AES-128-GCM using the
//! session key.  Each message begins with a 1-byte request-type field.
//!
//! Wire format: type_byte || rlp_list([field, ...])
//!
//! All six message types are implemented: PING, PONG, FINDNODE, NODES,
//! TALKREQ, TALKRES.

const std = @import("std");
const enr_mod = @import("../enr/enr.zig");

// Re-export RLP helpers from the ENR module for callers that need them.
pub const rlpEncodeString = enr_mod.rlpEncodeString;
pub const rlpEncodeUint64 = enr_mod.rlpEncodeUint64;
pub const rlpEncodeList = enr_mod.rlpEncodeList;
pub const rlpDecode = enr_mod.rlpDecode;
pub const rlpStringValue = enr_mod.rlpStringValue;

// ---------------------------------------------------------------------------
// Message type constants (discv5 spec §10)
// ---------------------------------------------------------------------------

pub const msg_ping: u8 = 0x01;
pub const msg_pong: u8 = 0x02;
pub const msg_findnode: u8 = 0x03;
pub const msg_nodes: u8 = 0x04;
pub const msg_talkreq: u8 = 0x05;
pub const msg_talkres: u8 = 0x06;

// ---------------------------------------------------------------------------
// Protocol parameters
// ---------------------------------------------------------------------------

/// Maximum number of ENRs returned in a single NODES reply.
pub const max_nodes_per_response: usize = 4;

/// Maximum payload size for TALKREQ / TALKRES (discv5 spec recommendation).
pub const max_talk_payload: usize = 1200;

/// Request timeout (how long to wait before re-sending or giving up).
pub const request_timeout_ms: u64 = 500;

/// Maximum number of concurrent in-flight requests per peer.
pub const max_in_flight: usize = 3;

// ---------------------------------------------------------------------------
// Message structs
// ---------------------------------------------------------------------------

pub const Ping = struct {
    request_id: u64,
    enr_seq: u64,
};

pub const Pong = struct {
    request_id: u64,
    enr_seq: u64,
    /// Observed IP bytes (4 bytes for IPv4, 16 for IPv6).
    recipient_ip: [16]u8,
    ip_len: u8, // 4 or 16
    recipient_port: u16,
};

pub const FindNode = struct {
    request_id: u64,
    /// Log-distance values (1–256). Each is encoded as a u8.
    distances: []const u8,
};

pub const Nodes = struct {
    request_id: u64,
    /// Total number of NODES packets in this response series.
    total: u8,
    /// RLP-encoded ENR records (each up to 300 bytes).
    enrs: []const []const u8,
};

pub const TalkReq = struct {
    request_id: u64,
    protocol: []const u8,
    payload: []const u8,
};

pub const TalkRes = struct {
    request_id: u64,
    payload: []const u8,
};

/// TALKREQ protocol string for ethp2p capability exchange.
pub const talk_protocol_eth_ec: []const u8 = "eth-ec/1";

// ---------------------------------------------------------------------------
// Encode errors
// ---------------------------------------------------------------------------

pub const EncodeError = std.mem.Allocator.Error;
pub const DecodeError = enr_mod.EnrError || error{UnknownType};

// ---------------------------------------------------------------------------
// Encode helpers
// ---------------------------------------------------------------------------

/// Encode a request-id as a variable-length integer (1–8 bytes, big-endian,
/// minimal — no leading zeros, per discv5 spec).
fn encodeReqId(allocator: std.mem.Allocator, id: u64) EncodeError![]u8 {
    return rlpEncodeUint64(allocator, id);
}

/// Append `buf` to `items`, freeing `buf` on allocation failure so the caller's
/// nested-try expression cannot leak the freshly encoded slice.
fn appendOwned(
    items: *std.ArrayListUnmanaged([]u8),
    allocator: std.mem.Allocator,
    buf: []u8,
) std.mem.Allocator.Error!void {
    items.append(allocator, buf) catch |err| {
        allocator.free(buf);
        return err;
    };
}

/// Decode a request-id from an RLP item (variable-length integer).
fn decodeReqId(item: []const u8) DecodeError!u64 {
    const bytes = try rlpStringValue(item);
    var v: u64 = 0;
    for (bytes) |b| v = (v << 8) | b;
    return v;
}

// ---------------------------------------------------------------------------
// PING
// ---------------------------------------------------------------------------

pub fn encodePing(allocator: std.mem.Allocator, msg: Ping) EncodeError![]u8 {
    var items = std.ArrayListUnmanaged([]u8){};
    defer {
        for (items.items) |it| allocator.free(it);
        items.deinit(allocator);
    }

    try appendOwned(&items, allocator, try encodeReqId(allocator, msg.request_id));
    try appendOwned(&items, allocator, try rlpEncodeUint64(allocator, msg.enr_seq));

    const body = try rlpEncodeList(allocator, @ptrCast(items.items));
    defer allocator.free(body);

    const out = try allocator.alloc(u8, 1 + body.len);
    out[0] = msg_ping;
    @memcpy(out[1..], body);
    return out;
}

pub fn decodePing(allocator: std.mem.Allocator, data: []const u8) DecodeError!Ping {
    if (data.len < 2 or data[0] != msg_ping) return error.BadRlp;
    const payload = try enr_mod.rlpListPayload(data[1..]);
    var rest = payload;

    const id_item = try rlpDecode(rest);
    rest = id_item.rest;
    const seq_item = try rlpDecode(rest);
    _ = allocator;

    return .{
        .request_id = try decodeReqId(id_item.item),
        .enr_seq = try decodeReqId(seq_item.item),
    };
}

// ---------------------------------------------------------------------------
// PONG
// ---------------------------------------------------------------------------

pub fn encodePong(allocator: std.mem.Allocator, msg: Pong) EncodeError![]u8 {
    var items = std.ArrayListUnmanaged([]u8){};
    defer {
        for (items.items) |it| allocator.free(it);
        items.deinit(allocator);
    }

    try appendOwned(&items, allocator, try encodeReqId(allocator, msg.request_id));
    try appendOwned(&items, allocator, try rlpEncodeUint64(allocator, msg.enr_seq));
    try appendOwned(&items, allocator, try rlpEncodeString(allocator, msg.recipient_ip[0..msg.ip_len]));
    try appendOwned(&items, allocator, try rlpEncodeUint64(allocator, msg.recipient_port));

    const body = try rlpEncodeList(allocator, @ptrCast(items.items));
    defer allocator.free(body);

    const out = try allocator.alloc(u8, 1 + body.len);
    out[0] = msg_pong;
    @memcpy(out[1..], body);
    return out;
}

pub fn decodePong(allocator: std.mem.Allocator, data: []const u8) (DecodeError || std.mem.Allocator.Error)!Pong {
    if (data.len < 2 or data[0] != msg_pong) return error.BadRlp;
    const payload = try enr_mod.rlpListPayload(data[1..]);
    var rest = payload;

    const id_item = try rlpDecode(rest);
    rest = id_item.rest;
    const seq_item = try rlpDecode(rest);
    rest = seq_item.rest;
    const ip_item = try rlpDecode(rest);
    rest = ip_item.rest;
    const port_item = try rlpDecode(rest);
    _ = allocator;

    const ip_bytes = try rlpStringValue(ip_item.item);
    var ip: [16]u8 = [_]u8{0} ** 16;
    const ip_len: u8 = @intCast(@min(16, ip_bytes.len));
    @memcpy(ip[0..ip_len], ip_bytes[0..ip_len]);

    return .{
        .request_id = try decodeReqId(id_item.item),
        .enr_seq = try decodeReqId(seq_item.item),
        .recipient_ip = ip,
        .ip_len = ip_len,
        .recipient_port = @intCast(try decodeReqId(port_item.item)),
    };
}

// ---------------------------------------------------------------------------
// FINDNODE
// ---------------------------------------------------------------------------

pub fn encodeFindNode(allocator: std.mem.Allocator, msg: FindNode) EncodeError![]u8 {
    var items = std.ArrayListUnmanaged([]u8){};
    defer {
        for (items.items) |it| allocator.free(it);
        items.deinit(allocator);
    }

    try appendOwned(&items, allocator, try encodeReqId(allocator, msg.request_id));

    // distances is a list of u8 values.
    var dist_items = std.ArrayListUnmanaged([]u8){};
    defer {
        for (dist_items.items) |it| allocator.free(it);
        dist_items.deinit(allocator);
    }
    for (msg.distances) |d| {
        try appendOwned(&dist_items, allocator, try rlpEncodeUint64(allocator, d));
    }
    try appendOwned(&items, allocator, try rlpEncodeList(allocator, @ptrCast(dist_items.items)));

    const body = try rlpEncodeList(allocator, @ptrCast(items.items));
    defer allocator.free(body);

    const out = try allocator.alloc(u8, 1 + body.len);
    out[0] = msg_findnode;
    @memcpy(out[1..], body);
    return out;
}

pub fn decodeFindNode(allocator: std.mem.Allocator, data: []const u8) (DecodeError || std.mem.Allocator.Error)!FindNode {
    if (data.len < 2 or data[0] != msg_findnode) return error.BadRlp;
    const payload = try enr_mod.rlpListPayload(data[1..]);
    var rest = payload;

    const id_item = try rlpDecode(rest);
    rest = id_item.rest;
    const dists_item = try rlpDecode(rest);
    const dists_payload = try enr_mod.rlpListPayload(dists_item.item);

    var dist_list = std.ArrayListUnmanaged(u8){};
    errdefer dist_list.deinit(allocator);
    var dr = dists_payload;
    while (dr.len > 0) {
        const d_item = try rlpDecode(dr);
        dr = d_item.rest;
        try dist_list.append(allocator, @intCast(try decodeReqId(d_item.item)));
    }

    return .{
        .request_id = try decodeReqId(id_item.item),
        .distances = try dist_list.toOwnedSlice(allocator),
    };
}

pub fn freeFindNode(allocator: std.mem.Allocator, msg: FindNode) void {
    allocator.free(msg.distances);
}

// ---------------------------------------------------------------------------
// NODES
// ---------------------------------------------------------------------------

pub fn encodeNodes(allocator: std.mem.Allocator, msg: Nodes) EncodeError![]u8 {
    var items = std.ArrayListUnmanaged([]u8){};
    defer {
        for (items.items) |it| allocator.free(it);
        items.deinit(allocator);
    }

    try appendOwned(&items, allocator, try encodeReqId(allocator, msg.request_id));
    try appendOwned(&items, allocator, try rlpEncodeUint64(allocator, msg.total));

    var enr_items = std.ArrayListUnmanaged([]u8){};
    defer {
        for (enr_items.items) |it| allocator.free(it);
        enr_items.deinit(allocator);
    }
    for (msg.enrs) |enr_bytes| {
        try appendOwned(&enr_items, allocator, try allocator.dupe(u8, enr_bytes));
    }
    try appendOwned(&items, allocator, try rlpEncodeList(allocator, @ptrCast(enr_items.items)));

    const body = try rlpEncodeList(allocator, @ptrCast(items.items));
    defer allocator.free(body);

    const out = try allocator.alloc(u8, 1 + body.len);
    out[0] = msg_nodes;
    @memcpy(out[1..], body);
    return out;
}

pub fn decodeNodes(allocator: std.mem.Allocator, data: []const u8) (DecodeError || std.mem.Allocator.Error)!Nodes {
    if (data.len < 2 or data[0] != msg_nodes) return error.BadRlp;
    const payload = try enr_mod.rlpListPayload(data[1..]);
    var rest = payload;

    const id_item = try rlpDecode(rest);
    rest = id_item.rest;
    const total_item = try rlpDecode(rest);
    rest = total_item.rest;
    const enrs_item = try rlpDecode(rest);
    const enrs_payload = try enr_mod.rlpListPayload(enrs_item.item);

    var enr_list = std.ArrayListUnmanaged([]const u8){};
    errdefer {
        for (enr_list.items) |e| allocator.free(e);
        enr_list.deinit(allocator);
    }
    var er = enrs_payload;
    while (er.len > 0) {
        const e = try rlpDecode(er);
        er = e.rest;
        const copy = try allocator.dupe(u8, e.item);
        enr_list.append(allocator, copy) catch |err| {
            allocator.free(copy);
            return err;
        };
    }

    return .{
        .request_id = try decodeReqId(id_item.item),
        .total = @intCast(try decodeReqId(total_item.item)),
        .enrs = try enr_list.toOwnedSlice(allocator),
    };
}

pub fn freeNodes(allocator: std.mem.Allocator, msg: Nodes) void {
    for (msg.enrs) |e| allocator.free(e);
    allocator.free(msg.enrs);
}

// ---------------------------------------------------------------------------
// TALKREQ
// ---------------------------------------------------------------------------

pub fn encodeTalkReq(allocator: std.mem.Allocator, msg: TalkReq) EncodeError![]u8 {
    var items = std.ArrayListUnmanaged([]u8){};
    defer {
        for (items.items) |it| allocator.free(it);
        items.deinit(allocator);
    }

    try appendOwned(&items, allocator, try encodeReqId(allocator, msg.request_id));
    try appendOwned(&items, allocator, try rlpEncodeString(allocator, msg.protocol));
    try appendOwned(&items, allocator, try rlpEncodeString(allocator, msg.payload));

    const body = try rlpEncodeList(allocator, @ptrCast(items.items));
    defer allocator.free(body);

    const out = try allocator.alloc(u8, 1 + body.len);
    out[0] = msg_talkreq;
    @memcpy(out[1..], body);
    return out;
}

pub fn decodeTalkReq(allocator: std.mem.Allocator, data: []const u8) (DecodeError || std.mem.Allocator.Error)!TalkReq {
    if (data.len < 2 or data[0] != msg_talkreq) return error.BadRlp;
    const payload = try enr_mod.rlpListPayload(data[1..]);
    var rest = payload;

    const id_item = try rlpDecode(rest);
    rest = id_item.rest;
    const proto_item = try rlpDecode(rest);
    rest = proto_item.rest;
    const payload_item = try rlpDecode(rest);

    return .{
        .request_id = try decodeReqId(id_item.item),
        .protocol = try allocator.dupe(u8, try rlpStringValue(proto_item.item)),
        .payload = try allocator.dupe(u8, try rlpStringValue(payload_item.item)),
    };
}

pub fn freeTalkReq(allocator: std.mem.Allocator, msg: TalkReq) void {
    allocator.free(msg.protocol);
    allocator.free(msg.payload);
}

// ---------------------------------------------------------------------------
// TALKRES
// ---------------------------------------------------------------------------

pub fn encodeTalkRes(allocator: std.mem.Allocator, msg: TalkRes) EncodeError![]u8 {
    var items = std.ArrayListUnmanaged([]u8){};
    defer {
        for (items.items) |it| allocator.free(it);
        items.deinit(allocator);
    }

    try appendOwned(&items, allocator, try encodeReqId(allocator, msg.request_id));
    try appendOwned(&items, allocator, try rlpEncodeString(allocator, msg.payload));

    const body = try rlpEncodeList(allocator, @ptrCast(items.items));
    defer allocator.free(body);

    const out = try allocator.alloc(u8, 1 + body.len);
    out[0] = msg_talkres;
    @memcpy(out[1..], body);
    return out;
}

pub fn decodeTalkRes(allocator: std.mem.Allocator, data: []const u8) (DecodeError || std.mem.Allocator.Error)!TalkRes {
    if (data.len < 2 or data[0] != msg_talkres) return error.BadRlp;
    const payload = try enr_mod.rlpListPayload(data[1..]);
    var rest = payload;

    const id_item = try rlpDecode(rest);
    rest = id_item.rest;
    const payload_item = try rlpDecode(rest);

    return .{
        .request_id = try decodeReqId(id_item.item),
        .payload = try allocator.dupe(u8, try rlpStringValue(payload_item.item)),
    };
}

pub fn freeTalkRes(allocator: std.mem.Allocator, msg: TalkRes) void {
    allocator.free(msg.payload);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "message type constants are distinct" {
    const types = [_]u8{ msg_ping, msg_pong, msg_findnode, msg_nodes, msg_talkreq, msg_talkres };
    for (types, 0..) |a, i| {
        for (types[i + 1 ..]) |b| {
            try std.testing.expect(a != b);
        }
    }
}

test "protocol limits are sensible" {
    try std.testing.expect(max_nodes_per_response > 0);
    try std.testing.expect(max_talk_payload >= 256);
    try std.testing.expect(request_timeout_ms > 0);
}

test "PING encode/decode roundtrip" {
    const gpa = std.testing.allocator;
    const msg = Ping{ .request_id = 42, .enr_seq = 7 };
    const enc = try encodePing(gpa, msg);
    defer gpa.free(enc);
    const dec = try decodePing(gpa, enc);
    try std.testing.expectEqual(msg.request_id, dec.request_id);
    try std.testing.expectEqual(msg.enr_seq, dec.enr_seq);
}

test "PONG encode/decode roundtrip" {
    const gpa = std.testing.allocator;
    const ip = [_]u8{ 192, 168, 1, 1 };
    var ip16: [16]u8 = [_]u8{0} ** 16;
    @memcpy(ip16[0..4], &ip);
    const msg = Pong{
        .request_id = 99,
        .enr_seq = 3,
        .recipient_ip = ip16,
        .ip_len = 4,
        .recipient_port = 9000,
    };
    const enc = try encodePong(gpa, msg);
    defer gpa.free(enc);
    const dec = try decodePong(gpa, enc);
    try std.testing.expectEqual(msg.request_id, dec.request_id);
    try std.testing.expectEqual(msg.recipient_port, dec.recipient_port);
    try std.testing.expectEqual(@as(u8, 4), dec.ip_len);
    try std.testing.expectEqualSlices(u8, msg.recipient_ip[0..4], dec.recipient_ip[0..4]);
}

test "FINDNODE encode/decode roundtrip" {
    const gpa = std.testing.allocator;
    const distances = &[_]u8{ 255, 254, 253 };
    const msg = FindNode{ .request_id = 1, .distances = distances };
    const enc = try encodeFindNode(gpa, msg);
    defer gpa.free(enc);
    const dec = try decodeFindNode(gpa, enc);
    defer freeFindNode(gpa, dec);
    try std.testing.expectEqual(msg.request_id, dec.request_id);
    try std.testing.expectEqualSlices(u8, distances, dec.distances);
}

test "NODES encode/decode roundtrip" {
    const gpa = std.testing.allocator;
    const fake_enr = &[_]u8{ 0xc4, 0x01, 0x02, 0x03, 0x04 }; // short list
    const enrs = &[_][]const u8{fake_enr};
    const msg = Nodes{ .request_id = 7, .total = 1, .enrs = enrs };
    const enc = try encodeNodes(gpa, msg);
    defer gpa.free(enc);
    const dec = try decodeNodes(gpa, enc);
    defer freeNodes(gpa, dec);
    try std.testing.expectEqual(msg.request_id, dec.request_id);
    try std.testing.expectEqual(@as(u8, 1), dec.total);
    try std.testing.expectEqual(@as(usize, 1), dec.enrs.len);
    try std.testing.expectEqualSlices(u8, fake_enr, dec.enrs[0]);
}

test "TALKREQ encode/decode roundtrip" {
    const gpa = std.testing.allocator;
    const msg = TalkReq{
        .request_id = 5,
        .protocol = talk_protocol_eth_ec,
        .payload = "hello",
    };
    const enc = try encodeTalkReq(gpa, msg);
    defer gpa.free(enc);
    const dec = try decodeTalkReq(gpa, enc);
    defer freeTalkReq(gpa, dec);
    try std.testing.expectEqual(msg.request_id, dec.request_id);
    try std.testing.expectEqualStrings(msg.protocol, dec.protocol);
    try std.testing.expectEqualStrings(msg.payload, dec.payload);
}

test "TALKRES encode/decode roundtrip" {
    const gpa = std.testing.allocator;
    const msg = TalkRes{ .request_id = 8, .payload = "world" };
    const enc = try encodeTalkRes(gpa, msg);
    defer gpa.free(enc);
    const dec = try decodeTalkRes(gpa, enc);
    defer freeTalkRes(gpa, dec);
    try std.testing.expectEqual(msg.request_id, dec.request_id);
    try std.testing.expectEqualStrings(msg.payload, dec.payload);
}
