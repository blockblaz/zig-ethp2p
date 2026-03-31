//! Subset of [go-libp2p-pubsub `rpc.proto`](https://github.com/libp2p/go-libp2p-pubsub/blob/master/pb/rpc.proto):
//! `ControlIHave` and `ControlIWant` only (length-delimited string fields, proto2-compatible wire).
//! Does not build full `RPC` frames; embed returned blobs inside your transport as needed.

const std = @import("std");
const varint = @import("../wire/varint.zig");

const Allocator = std.mem.Allocator;

fn appendVarintUnmanaged(list: *std.ArrayListUnmanaged(u8), allocator: Allocator, value: u64) Allocator.Error!void {
    var v = value;
    while (v >= 0x80) {
        try list.append(allocator, @as(u8, @truncate(v & 0x7f | 0x80)));
        v >>= 7;
    }
    try list.append(allocator, @as(u8, @truncate(v)));
}

pub const DecodeError = varint.DecodeError || error{ BadWireType, BadTag };

pub const IHave = struct {
    topic_id: ?[]const u8,
    message_ids: []const []const u8,
};

pub const IHaveOwned = struct {
    topic_id: ?[]u8,
    message_ids: [][]u8,

    pub fn deinit(self: *IHaveOwned, allocator: Allocator) void {
        if (self.topic_id) |t| allocator.free(t);
        for (self.message_ids) |m| allocator.free(m);
        allocator.free(self.message_ids);
        self.* = undefined;
    }
};

pub const IWantOwned = struct {
    message_ids: [][]u8,

    pub fn deinit(self: *IWantOwned, allocator: Allocator) void {
        for (self.message_ids) |m| allocator.free(m);
        allocator.free(self.message_ids);
        self.* = undefined;
    }
};

fn appendTagLenBytes(list: *std.ArrayListUnmanaged(u8), allocator: Allocator, field_num: u32, payload: []const u8) Allocator.Error!void {
    const tag: u8 = @truncate((field_num << 3) | 2);
    try list.append(allocator, tag);
    try appendVarintUnmanaged(list, allocator, @as(u64, @intCast(payload.len)));
    try list.appendSlice(allocator, payload);
}

/// Serializes `ControlIHave` (message body only, not wrapped in `ControlMessage`).
pub fn encodeIHave(allocator: Allocator, topic: ?[]const u8, message_ids: []const []const u8) Allocator.Error![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .{};
    errdefer list.deinit(allocator);
    if (topic) |t| {
        try appendTagLenBytes(&list, allocator, 1, t);
    }
    for (message_ids) |mid| {
        try appendTagLenBytes(&list, allocator, 2, mid);
    }
    return try list.toOwnedSlice(allocator);
}

/// Serializes `ControlIWant` (message body only).
pub fn encodeIWant(allocator: Allocator, message_ids: []const []const u8) Allocator.Error![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .{};
    errdefer list.deinit(allocator);
    for (message_ids) |mid| {
        try appendTagLenBytes(&list, allocator, 1, mid);
    }
    return try list.toOwnedSlice(allocator);
}

/// Wraps one `encodeIHave` payload as `ControlMessage.ihave` (field 1, repeated).
pub fn encodeControlMessageSingleIHave(allocator: Allocator, ihave_body: []const u8) Allocator.Error![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .{};
    errdefer list.deinit(allocator);
    try appendTagLenBytes(&list, allocator, 1, ihave_body);
    return try list.toOwnedSlice(allocator);
}

fn decodeTagLen(buf: []const u8, offset: *usize) DecodeError!struct { field: u32, payload: []const u8 } {
    if (offset.* >= buf.len) return error.Truncated;
    const tag = try varint.decode(buf, offset);
    const field: u32 = @intCast(tag >> 3);
    const wire: u32 = @intCast(tag & 7);
    if (wire != 2) return error.BadWireType;
    const plen = try varint.decode(buf, offset);
    if (buf.len - offset.* < plen) return error.Truncated;
    const start = offset.*;
    offset.* += @intCast(plen);
    return .{ .field = field, .payload = buf[start..][0..@intCast(plen)] };
}

pub fn decodeIHaveOwned(allocator: Allocator, buf: []const u8) (DecodeError || Allocator.Error)!IHaveOwned {
    var offset: usize = 0;
    var topic: ?[]u8 = null;
    var ids: std.ArrayListUnmanaged([]u8) = .{};
    errdefer {
        if (topic) |t| allocator.free(t);
        for (ids.items) |m| allocator.free(m);
        ids.deinit(allocator);
    }

    while (offset < buf.len) {
        const tl = try decodeTagLen(buf, &offset);
        switch (tl.field) {
            1 => {
                if (topic != null) return error.BadTag;
                topic = try allocator.dupe(u8, tl.payload);
            },
            2 => try ids.append(allocator, try allocator.dupe(u8, tl.payload)),
            else => return error.BadTag,
        }
    }

    return .{
        .topic_id = topic,
        .message_ids = try ids.toOwnedSlice(allocator),
    };
}

pub fn decodeIWantOwned(allocator: Allocator, buf: []const u8) (DecodeError || Allocator.Error)!IWantOwned {
    var offset: usize = 0;
    var ids: std.ArrayListUnmanaged([]u8) = .{};
    errdefer {
        for (ids.items) |m| allocator.free(m);
        ids.deinit(allocator);
    }

    while (offset < buf.len) {
        const tl = try decodeTagLen(buf, &offset);
        if (tl.field != 1) return error.BadTag;
        try ids.append(allocator, try allocator.dupe(u8, tl.payload));
    }

    return .{ .message_ids = try ids.toOwnedSlice(allocator) };
}

test "IHave roundtrip" {
    const gpa = std.testing.allocator;
    const enc = try encodeIHave(gpa, "broadcast-test", &.{ "a", "bb" });
    defer gpa.free(enc);

    var dec = try decodeIHaveOwned(gpa, enc);
    defer dec.deinit(gpa);

    try std.testing.expect(dec.topic_id != null);
    try std.testing.expectEqualStrings("broadcast-test", dec.topic_id.?);
    try std.testing.expectEqual(@as(usize, 2), dec.message_ids.len);
    try std.testing.expectEqualStrings("a", dec.message_ids[0]);
    try std.testing.expectEqualStrings("bb", dec.message_ids[1]);
}

test "IWant roundtrip" {
    const gpa = std.testing.allocator;
    const enc = try encodeIWant(gpa, &.{ "x", "yz" });
    defer gpa.free(enc);

    var dec = try decodeIWantOwned(gpa, enc);
    defer dec.deinit(gpa);

    try std.testing.expectEqual(@as(usize, 2), dec.message_ids.len);
    try std.testing.expectEqualStrings("x", dec.message_ids[0]);
    try std.testing.expectEqualStrings("yz", dec.message_ids[1]);
}

test "ControlMessage single IHave wrapper roundtrip" {
    const gpa = std.testing.allocator;
    const inner = try encodeIHave(gpa, "t", &.{"mid"});
    defer gpa.free(inner);
    const outer = try encodeControlMessageSingleIHave(gpa, inner);
    defer gpa.free(outer);

    var off: usize = 0;
    const tl = try decodeTagLen(outer, &off);
    try std.testing.expectEqual(@as(u32, 1), tl.field);
    try std.testing.expect(off == outer.len);

    var dec = try decodeIHaveOwned(gpa, tl.payload);
    defer dec.deinit(gpa);
    try std.testing.expectEqualStrings("t", dec.topic_id.?);
    try std.testing.expectEqualStrings("mid", dec.message_ids[0]);
}
