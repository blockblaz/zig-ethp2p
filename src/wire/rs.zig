const std = @import("std");
const varint = @import("varint.zig");

pub const Malformed = error{
    MalformedProtobuf,
    OutOfMemory,
} || varint.DecodeError;

fn appendTag(dst: *std.ArrayList(u8), gpa: std.mem.Allocator, field_num: u32, wire_type: u3) !void {
    const tag = (field_num << 3) | @as(u32, wire_type);
    try varint.append(dst, gpa, tag);
}

fn appendLenDelim(dst: *std.ArrayList(u8), allocator: std.mem.Allocator, field_num: u32, payload: []const u8) !void {
    try appendTag(dst, allocator, field_num, 2);
    try varint.append(dst, allocator, @intCast(payload.len));
    try dst.appendSlice(allocator, payload);
}

fn appendI32Field(dst: *std.ArrayList(u8), gpa: std.mem.Allocator, field_num: u32, value: i32) !void {
    try appendTag(dst, gpa, field_num, 0);
    const u = @as(u32, @bitCast(value));
    try varint.append(dst, gpa, u);
}

pub const Preamble = struct {
    num_data: i32,
    num_parity: i32,
    length: i32,
    hashes: []const []const u8,
    hash: []const u8,
};

pub fn encodePreamble(allocator: std.mem.Allocator, p: Preamble) ![]u8 {
    var dst = std.ArrayList(u8).empty;
    errdefer dst.deinit(allocator);
    try appendI32Field(&dst, allocator, 1, p.num_data);
    try appendI32Field(&dst, allocator, 2, p.num_parity);
    try appendI32Field(&dst, allocator, 3, p.length);
    for (p.hashes) |h| {
        try appendLenDelim(&dst, allocator, 4, h);
    }
    try appendLenDelim(&dst, allocator, 5, p.hash);
    return dst.toOwnedSlice(allocator);
}

fn skipField(buf: []const u8, offset: *usize, wire: u3) Malformed!void {
    switch (wire) {
        0 => _ = try varint.decode(buf, offset),
        1 => {
            if (offset.* + 8 > buf.len) return error.MalformedProtobuf;
            offset.* += 8;
        },
        2 => {
            const len_u = try varint.decode(buf, offset);
            const len: usize = @intCast(len_u);
            if (offset.* + len > buf.len) return error.MalformedProtobuf;
            offset.* += len;
        },
        5 => {
            if (offset.* + 4 > buf.len) return error.MalformedProtobuf;
            offset.* += 4;
        },
        else => return error.MalformedProtobuf,
    }
}

fn decodeBytes(buf: []const u8, allocator: std.mem.Allocator, offset: *usize) Malformed![]const u8 {
    const len_u = try varint.decode(buf, offset);
    const len: usize = @intCast(len_u);
    if (offset.* + len > buf.len) return error.MalformedProtobuf;
    const s = try allocator.dupe(u8, buf[offset.* .. offset.* + len]);
    offset.* += len;
    return s;
}

pub const PreambleOwned = struct {
    num_data: i32,
    num_parity: i32,
    length: i32,
    hashes: [][]const u8,
    hash: []const u8,

    pub fn deinit(self: *PreambleOwned, allocator: std.mem.Allocator) void {
        for (self.hashes) |h| allocator.free(h);
        allocator.free(self.hashes);
        allocator.free(self.hash);
    }
};

pub fn decodePreamble(allocator: std.mem.Allocator, buf: []const u8) Malformed!PreambleOwned {
    // Proto3 omits zero-valued scalars on the wire; defaults match Go unmarshaling.
    var num_data: i32 = 0;
    var num_parity: i32 = 0;
    var length: i32 = 0;
    var hashes = std.ArrayList([]const u8).empty;
    errdefer {
        for (hashes.items) |h| allocator.free(h);
        hashes.deinit(allocator);
    }
    var hash: ?[]const u8 = null;
    errdefer if (hash) |h| allocator.free(h);

    var off: usize = 0;
    while (off < buf.len) {
        const tag = try varint.decode(buf, &off);
        const field = tag >> 3;
        const wire: u3 = @intCast(tag & 7);
        switch (field) {
            1 => {
                if (wire != 0) return error.MalformedProtobuf;
                num_data = try varint.decodeNonNegativeI32(buf, &off);
            },
            2 => {
                if (wire != 0) return error.MalformedProtobuf;
                num_parity = try varint.decodeNonNegativeI32(buf, &off);
            },
            3 => {
                if (wire != 0) return error.MalformedProtobuf;
                length = try varint.decodeNonNegativeI32(buf, &off);
            },
            4 => {
                if (wire != 2) return error.MalformedProtobuf;
                const b = try decodeBytes(buf, allocator, &off);
                try hashes.append(allocator, b);
            },
            5 => {
                if (wire != 2) return error.MalformedProtobuf;
                if (hash != null) return error.MalformedProtobuf;
                hash = try decodeBytes(buf, allocator, &off);
            },
            else => try skipField(buf, &off, wire),
        }
    }

    return .{
        .num_data = num_data,
        .num_parity = num_parity,
        .length = length,
        .hashes = try hashes.toOwnedSlice(allocator),
        .hash = hash orelse try allocator.dupe(u8, ""),
    };
}

pub const ChunkIdent = struct {
    index: i32,
};

pub fn encodeChunkIdent(allocator: std.mem.Allocator, c: ChunkIdent) ![]u8 {
    var dst = std.ArrayList(u8).empty;
    errdefer dst.deinit(allocator);
    try appendI32Field(&dst, allocator, 1, c.index);
    return dst.toOwnedSlice(allocator);
}

pub fn decodeChunkIdent(allocator: std.mem.Allocator, buf: []const u8) Malformed!ChunkIdent {
    _ = allocator;
    var off: usize = 0;
    var index: ?i32 = null;
    while (off < buf.len) {
        const tag = try varint.decode(buf, &off);
        const field = tag >> 3;
        const wire: u3 = @intCast(tag & 7);
        if (field == 1) {
            if (wire != 0) return error.MalformedProtobuf;
            index = try varint.decodeNonNegativeI32(buf, &off);
        } else {
            try skipField(buf, &off, wire);
        }
    }
    return .{ .index = index orelse 0 };
}

test "preamble golden and roundtrip" {
    const alloc = std.testing.allocator;
    var golden_buf: [32]u8 = undefined;
    const golden = try std.fmt.hexToBytes(&golden_buf, "08041002186422020102220203042a0405060708");

    const enc = try encodePreamble(alloc, .{
        .num_data = 4,
        .num_parity = 2,
        .length = 100,
        .hashes = &.{ &.{ 1, 2 }, &.{ 3, 4 } },
        .hash = &.{ 5, 6, 7, 8 },
    });
    defer alloc.free(enc);
    try std.testing.expectEqualSlices(u8, golden, enc);

    var dec = try decodePreamble(alloc, enc);
    defer dec.deinit(alloc);
    try std.testing.expectEqual(@as(i32, 4), dec.num_data);
    try std.testing.expectEqual(@as(i32, 2), dec.num_parity);
    try std.testing.expectEqual(@as(i32, 100), dec.length);
    try std.testing.expectEqual(@as(usize, 2), dec.hashes.len);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2 }, dec.hashes[0]);
    try std.testing.expectEqualSlices(u8, &.{ 3, 4 }, dec.hashes[1]);
    try std.testing.expectEqualSlices(u8, &.{ 5, 6, 7, 8 }, dec.hash);
}

test "chunk ident roundtrip" {
    const alloc = std.testing.allocator;
    const enc = try encodeChunkIdent(alloc, .{ .index = 42 });
    defer alloc.free(enc);
    const dec = try decodeChunkIdent(alloc, enc);
    try std.testing.expectEqual(@as(i32, 42), dec.index);
}
