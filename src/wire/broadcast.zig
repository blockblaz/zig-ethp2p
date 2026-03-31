const std = @import("std");
const varint = @import("varint.zig");

pub const Malformed = error{
    MalformedProtobuf,
    OutOfMemory,
} || varint.DecodeError;

fn appendTag(dst: *std.ArrayList(u8), allocator: std.mem.Allocator, field_num: u32, wire_type: u3) !void {
    const tag = (field_num << 3) | @as(u32, wire_type);
    try varint.append(dst, allocator, tag);
}

fn appendLenDelim(dst: *std.ArrayList(u8), allocator: std.mem.Allocator, field_num: u32, payload: []const u8) !void {
    try appendTag(dst, allocator, field_num, 2);
    try varint.append(dst, allocator, @intCast(payload.len));
    try dst.appendSlice(allocator, payload);
}

fn appendUInt32Field(dst: *std.ArrayList(u8), allocator: std.mem.Allocator, field_num: u32, value: u32) !void {
    try appendTag(dst, allocator, field_num, 0);
    try varint.append(dst, allocator, value);
}

fn appendStringField(dst: *std.ArrayList(u8), allocator: std.mem.Allocator, field_num: u32, value: []const u8) !void {
    try appendLenDelim(dst, allocator, field_num, value);
}

fn appendBytesField(dst: *std.ArrayList(u8), allocator: std.mem.Allocator, field_num: u32, value: []const u8) !void {
    try appendLenDelim(dst, allocator, field_num, value);
}

pub const Handshake = struct {
    version: u32,
    channels: []const []const u8,
    peer_id: []const u8,
};

pub const Subscribe = struct {
    channel: []const u8,
};

pub const Unsubscribe = struct {
    channel: []const u8,
};

pub const Bcast = union(enum) {
    peer_handshake: Handshake,
    channel_subscribe: Subscribe,
    channel_unsubscribe: Unsubscribe,
};

fn encodeHandshake(dst: *std.ArrayList(u8), allocator: std.mem.Allocator, h: Handshake) !void {
    try appendUInt32Field(dst, allocator, 1, h.version);
    for (h.channels) |ch| {
        try appendStringField(dst, allocator, 2, ch);
    }
    try appendStringField(dst, allocator, 3, h.peer_id);
}

pub fn encodeBcast(allocator: std.mem.Allocator, msg: Bcast) ![]u8 {
    var dst = std.ArrayList(u8).empty;
    errdefer dst.deinit(allocator);

    switch (msg) {
        .peer_handshake => |h| {
            var inner = std.ArrayList(u8).empty;
            defer inner.deinit(allocator);
            try encodeHandshake(&inner, allocator, h);
            try appendLenDelim(&dst, allocator, 1, inner.items);
        },
        .channel_subscribe => |s| {
            var inner = std.ArrayList(u8).empty;
            defer inner.deinit(allocator);
            try appendStringField(&inner, allocator, 1, s.channel);
            try appendLenDelim(&dst, allocator, 2, inner.items);
        },
        .channel_unsubscribe => |u| {
            var inner = std.ArrayList(u8).empty;
            defer inner.deinit(allocator);
            try appendStringField(&inner, allocator, 1, u.channel);
            try appendLenDelim(&dst, allocator, 3, inner.items);
        },
    }

    return dst.toOwnedSlice(allocator);
}

pub const SessOpen = struct {
    channel: []const u8,
    message_id: []const u8,
    preamble: []const u8,
    initial_update: []const u8,
};

pub const SessUpdate = struct {
    data: []const u8,
};

pub const Sess = union(enum) {
    session_open: SessOpen,
    routing_update: SessUpdate,
};

fn encodeSessOpen(dst: *std.ArrayList(u8), allocator: std.mem.Allocator, o: SessOpen) !void {
    try appendStringField(dst, allocator, 1, o.channel);
    try appendStringField(dst, allocator, 2, o.message_id);
    try appendBytesField(dst, allocator, 3, o.preamble);
    try appendBytesField(dst, allocator, 4, o.initial_update);
}

pub fn encodeSess(allocator: std.mem.Allocator, msg: Sess) ![]u8 {
    var dst = std.ArrayList(u8).empty;
    errdefer dst.deinit(allocator);

    switch (msg) {
        .session_open => |o| {
            var inner = std.ArrayList(u8).empty;
            defer inner.deinit(allocator);
            try encodeSessOpen(&inner, allocator, o);
            try appendLenDelim(&dst, allocator, 1, inner.items);
        },
        .routing_update => |u| {
            var inner = std.ArrayList(u8).empty;
            defer inner.deinit(allocator);
            try appendBytesField(&inner, allocator, 1, u.data);
            try appendLenDelim(&dst, allocator, 2, inner.items);
        },
    }

    return dst.toOwnedSlice(allocator);
}

pub const ChunkHeader = struct {
    channel: []const u8,
    message_id: []const u8,
    chunk_id: []const u8,
    data_length: u32,
};

pub fn encodeChunkHeader(allocator: std.mem.Allocator, h: ChunkHeader) ![]u8 {
    var dst = std.ArrayList(u8).empty;
    errdefer dst.deinit(allocator);
    try appendStringField(&dst, allocator, 1, h.channel);
    try appendStringField(&dst, allocator, 2, h.message_id);
    try appendBytesField(&dst, allocator, 3, h.chunk_id);
    try appendUInt32Field(&dst, allocator, 4, h.data_length);
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

fn decodeString(buf: []const u8, allocator: std.mem.Allocator, offset: *usize) Malformed![]const u8 {
    const len_u = try varint.decode(buf, offset);
    const len: usize = @intCast(len_u);
    if (offset.* + len > buf.len) return error.MalformedProtobuf;
    const s = try allocator.dupe(u8, buf[offset.* .. offset.* + len]);
    offset.* += len;
    return s;
}

fn decodeBytes(buf: []const u8, allocator: std.mem.Allocator, offset: *usize) Malformed![]const u8 {
    return decodeString(buf, allocator, offset);
}

fn decodeHandshake(buf: []const u8, allocator: std.mem.Allocator) Malformed!struct {
    version: u32,
    channels: [][]const u8,
    peer_id: []const u8,
} {
    var version: u32 = 0;
    var channels = std.ArrayList([]const u8).empty;
    errdefer {
        for (channels.items) |s| allocator.free(s);
        channels.deinit(allocator);
    }
    var peer_id: ?[]const u8 = null;
    errdefer if (peer_id) |p| allocator.free(p);

    var off: usize = 0;
    while (off < buf.len) {
        const tag = try varint.decode(buf, &off);
        const field = tag >> 3;
        const wire: u3 = @intCast(tag & 7);
        switch (field) {
            1 => {
                if (wire != 0) return error.MalformedProtobuf;
                version = @intCast(try varint.decode(buf, &off));
            },
            2 => {
                if (wire != 2) return error.MalformedProtobuf;
                const s = try decodeString(buf, allocator, &off);
                try channels.append(allocator, s);
            },
            3 => {
                if (wire != 2) return error.MalformedProtobuf;
                if (peer_id != null) return error.MalformedProtobuf;
                peer_id = try decodeString(buf, allocator, &off);
            },
            else => try skipField(buf, &off, wire),
        }
    }

    const pid = peer_id orelse return error.MalformedProtobuf;
    return .{
        .version = version,
        .channels = try channels.toOwnedSlice(allocator),
        .peer_id = pid,
    };
}

pub const BcastOwned = union(enum) {
    peer_handshake: struct {
        version: u32,
        channels: [][]const u8,
        peer_id: []const u8,
    },
    channel_subscribe: struct { channel: []const u8 },
    channel_unsubscribe: struct { channel: []const u8 },

    pub fn deinit(self: *BcastOwned, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .peer_handshake => |*h| {
                for (h.channels) |c| allocator.free(c);
                allocator.free(h.channels);
                allocator.free(h.peer_id);
            },
            .channel_subscribe => |*s| allocator.free(s.channel),
            .channel_unsubscribe => |*u| allocator.free(u.channel),
        }
    }
};

pub fn decodeBcast(allocator: std.mem.Allocator, buf: []const u8) Malformed!BcastOwned {
    var off: usize = 0;
    var which: ?enum { h, s, u } = null;
    var payload: ?[]const u8 = null;
    errdefer if (payload) |p| allocator.free(p);

    while (off < buf.len) {
        const tag = try varint.decode(buf, &off);
        const field = tag >> 3;
        const wire: u3 = @intCast(tag & 7);
        if (wire != 2) return error.MalformedProtobuf;
        const inner = try decodeBytes(buf, allocator, &off);
        switch (field) {
            1 => {
                if (which != null) return error.MalformedProtobuf;
                which = .h;
                payload = inner;
            },
            2 => {
                if (which != null) return error.MalformedProtobuf;
                which = .s;
                payload = inner;
            },
            3 => {
                if (which != null) return error.MalformedProtobuf;
                which = .u;
                payload = inner;
            },
            else => allocator.free(inner),
        }
    }

    const p = payload orelse return error.MalformedProtobuf;
    errdefer allocator.free(p);

    switch (which.?) {
        .h => {
            const h = try decodeHandshake(p, allocator);
            allocator.free(p);
            return .{ .peer_handshake = .{
                .version = h.version,
                .channels = h.channels,
                .peer_id = h.peer_id,
            } };
        },
        .s => {
            var io: usize = 0;
            var ch: ?[]const u8 = null;
            errdefer if (ch) |c| allocator.free(c);
            while (io < p.len) {
                const t = try varint.decode(p, &io);
                const f = t >> 3;
                const w: u3 = @intCast(t & 7);
                if (f == 1) {
                    if (w != 2) return error.MalformedProtobuf;
                    if (ch != null) return error.MalformedProtobuf;
                    ch = try decodeString(p, allocator, &io);
                } else {
                    try skipField(p, &io, w);
                }
            }
            const channel = ch orelse return error.MalformedProtobuf;
            allocator.free(p);
            return .{ .channel_subscribe = .{ .channel = channel } };
        },
        .u => {
            var io: usize = 0;
            var ch: ?[]const u8 = null;
            errdefer if (ch) |c| allocator.free(c);
            while (io < p.len) {
                const t = try varint.decode(p, &io);
                const f = t >> 3;
                const w: u3 = @intCast(t & 7);
                if (f == 1) {
                    if (w != 2) return error.MalformedProtobuf;
                    if (ch != null) return error.MalformedProtobuf;
                    ch = try decodeString(p, allocator, &io);
                } else {
                    try skipField(p, &io, w);
                }
            }
            const channel = ch orelse return error.MalformedProtobuf;
            allocator.free(p);
            return .{ .channel_unsubscribe = .{ .channel = channel } };
        },
    }
}

pub const SessOwned = union(enum) {
    session_open: struct {
        channel: []const u8,
        message_id: []const u8,
        preamble: []const u8,
        initial_update: []const u8,
    },
    routing_update: struct { data: []const u8 },

    pub fn deinit(self: *SessOwned, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .session_open => |*o| {
                allocator.free(o.channel);
                allocator.free(o.message_id);
                allocator.free(o.preamble);
                allocator.free(o.initial_update);
            },
            .routing_update => |*u| allocator.free(u.data),
        }
    }
};

fn decodeSessOpen(buf: []const u8, allocator: std.mem.Allocator) Malformed!SessOwned {
    var channel: ?[]const u8 = null;
    var message_id: ?[]const u8 = null;
    var preamble: ?[]const u8 = null;
    var initial_update: ?[]const u8 = null;
    errdefer {
        if (channel) |s| allocator.free(s);
        if (message_id) |s| allocator.free(s);
        if (preamble) |s| allocator.free(s);
        if (initial_update) |s| allocator.free(s);
    }

    var off: usize = 0;
    while (off < buf.len) {
        const tag = try varint.decode(buf, &off);
        const field = tag >> 3;
        const wire: u3 = @intCast(tag & 7);
        switch (field) {
            1 => {
                if (wire != 2) return error.MalformedProtobuf;
                if (channel != null) return error.MalformedProtobuf;
                channel = try decodeString(buf, allocator, &off);
            },
            2 => {
                if (wire != 2) return error.MalformedProtobuf;
                if (message_id != null) return error.MalformedProtobuf;
                message_id = try decodeString(buf, allocator, &off);
            },
            3 => {
                if (wire != 2) return error.MalformedProtobuf;
                if (preamble != null) return error.MalformedProtobuf;
                preamble = try decodeBytes(buf, allocator, &off);
            },
            4 => {
                if (wire != 2) return error.MalformedProtobuf;
                if (initial_update != null) return error.MalformedProtobuf;
                initial_update = try decodeBytes(buf, allocator, &off);
            },
            else => try skipField(buf, &off, wire),
        }
    }

    return .{ .session_open = .{
        .channel = channel orelse return error.MalformedProtobuf,
        .message_id = message_id orelse return error.MalformedProtobuf,
        .preamble = preamble orelse return error.MalformedProtobuf,
        .initial_update = initial_update orelse return error.MalformedProtobuf,
    } };
}

pub fn decodeSess(allocator: std.mem.Allocator, buf: []const u8) Malformed!SessOwned {
    var off: usize = 0;
    var which: ?enum { open, upd } = null;
    var payload: ?[]const u8 = null;
    errdefer if (payload) |p| allocator.free(p);

    while (off < buf.len) {
        const tag = try varint.decode(buf, &off);
        const field = tag >> 3;
        const wire: u3 = @intCast(tag & 7);
        if (wire != 2) return error.MalformedProtobuf;
        const inner = try decodeBytes(buf, allocator, &off);
        switch (field) {
            1 => {
                if (which != null) return error.MalformedProtobuf;
                which = .open;
                payload = inner;
            },
            2 => {
                if (which != null) return error.MalformedProtobuf;
                which = .upd;
                payload = inner;
            },
            else => allocator.free(inner),
        }
    }

    const p = payload orelse return error.MalformedProtobuf;
    errdefer allocator.free(p);

    switch (which.?) {
        .open => {
            const o = try decodeSessOpen(p, allocator);
            allocator.free(p);
            return o;
        },
        .upd => {
            var io: usize = 0;
            var data: ?[]const u8 = null;
            errdefer if (data) |d| allocator.free(d);
            while (io < p.len) {
                const t = try varint.decode(p, &io);
                const f = t >> 3;
                const w: u3 = @intCast(t & 7);
                if (f == 1) {
                    if (w != 2) return error.MalformedProtobuf;
                    if (data != null) return error.MalformedProtobuf;
                    data = try decodeBytes(p, allocator, &io);
                } else {
                    try skipField(p, &io, w);
                }
            }
            const d = data orelse return error.MalformedProtobuf;
            allocator.free(p);
            return .{ .routing_update = .{ .data = d } };
        },
    }
}

pub const ChunkHeaderOwned = struct {
    channel: []const u8,
    message_id: []const u8,
    chunk_id: []const u8,
    data_length: u32,

    pub fn deinit(self: *ChunkHeaderOwned, allocator: std.mem.Allocator) void {
        allocator.free(self.channel);
        allocator.free(self.message_id);
        allocator.free(self.chunk_id);
    }
};

pub fn decodeChunkHeader(allocator: std.mem.Allocator, buf: []const u8) Malformed!ChunkHeaderOwned {
    var channel: ?[]const u8 = null;
    var message_id: ?[]const u8 = null;
    var chunk_id: ?[]const u8 = null;
    var data_length: u32 = 0;
    errdefer {
        if (channel) |s| allocator.free(s);
        if (message_id) |s| allocator.free(s);
        if (chunk_id) |s| allocator.free(s);
    }

    var off: usize = 0;
    while (off < buf.len) {
        const tag = try varint.decode(buf, &off);
        const field = tag >> 3;
        const wire: u3 = @intCast(tag & 7);
        switch (field) {
            1 => {
                if (wire != 2) return error.MalformedProtobuf;
                if (channel != null) return error.MalformedProtobuf;
                channel = try decodeString(buf, allocator, &off);
            },
            2 => {
                if (wire != 2) return error.MalformedProtobuf;
                if (message_id != null) return error.MalformedProtobuf;
                message_id = try decodeString(buf, allocator, &off);
            },
            3 => {
                if (wire != 2) return error.MalformedProtobuf;
                if (chunk_id != null) return error.MalformedProtobuf;
                chunk_id = try decodeBytes(buf, allocator, &off);
            },
            4 => {
                if (wire != 0) return error.MalformedProtobuf;
                data_length = @intCast(try varint.decode(buf, &off));
            },
            else => try skipField(buf, &off, wire),
        }
    }

    return .{
        .channel = channel orelse return error.MalformedProtobuf,
        .message_id = message_id orelse return error.MalformedProtobuf,
        .chunk_id = chunk_id orelse return error.MalformedProtobuf,
        .data_length = data_length,
    };
}

test "bcast handshake golden and roundtrip" {
    const alloc = std.testing.allocator;
    var golden_buf: [32]u8 = undefined;
    const golden = try std.fmt.hexToBytes(&golden_buf, "0a1708011206626c6f636b731204617474731a057065657231");

    const enc = try encodeBcast(alloc, .{ .peer_handshake = .{
        .version = 1,
        .channels = &.{ "blocks", "atts" },
        .peer_id = "peer1",
    } });
    defer alloc.free(enc);
    try std.testing.expectEqualSlices(u8, golden, enc);

    var dec = try decodeBcast(alloc, enc);
    defer dec.deinit(alloc);
    switch (dec) {
        .peer_handshake => |h| {
            try std.testing.expectEqual(@as(u32, 1), h.version);
            try std.testing.expectEqual(@as(usize, 2), h.channels.len);
            try std.testing.expectEqualStrings("blocks", h.channels[0]);
            try std.testing.expectEqualStrings("atts", h.channels[1]);
            try std.testing.expectEqualStrings("peer1", h.peer_id);
        },
        else => return error.TestUnexpectedVariant,
    }
}

test "sess open golden and roundtrip" {
    const alloc = std.testing.allocator;
    var golden_buf: [32]u8 = undefined;
    const golden = try std.fmt.hexToBytes(&golden_buf, "0a130a0363683112036d69641a0301020322020405");

    const enc = try encodeSess(alloc, .{ .session_open = .{
        .channel = "ch1",
        .message_id = "mid",
        .preamble = &.{ 1, 2, 3 },
        .initial_update = &.{ 4, 5 },
    } });
    defer alloc.free(enc);
    try std.testing.expectEqualSlices(u8, golden, enc);

    var dec = try decodeSess(alloc, enc);
    defer dec.deinit(alloc);
    switch (dec) {
        .session_open => |o| {
            try std.testing.expectEqualStrings("ch1", o.channel);
            try std.testing.expectEqualStrings("mid", o.message_id);
            try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, o.preamble);
            try std.testing.expectEqualSlices(u8, &.{ 4, 5 }, o.initial_update);
        },
        else => return error.TestUnexpectedVariant,
    }
}

test "chunk header golden and roundtrip" {
    const alloc = std.testing.allocator;
    var golden_buf: [32]u8 = undefined;
    const golden = try std.fmt.hexToBytes(&golden_buf, "0a016312016d1a0109202a");

    const enc = try encodeChunkHeader(alloc, .{
        .channel = "c",
        .message_id = "m",
        .chunk_id = &.{9},
        .data_length = 42,
    });
    defer alloc.free(enc);
    try std.testing.expectEqualSlices(u8, golden, enc);

    var dec = try decodeChunkHeader(alloc, enc);
    defer dec.deinit(alloc);
    try std.testing.expectEqualStrings("c", dec.channel);
    try std.testing.expectEqualStrings("m", dec.message_id);
    try std.testing.expectEqualSlices(u8, &.{9}, dec.chunk_id);
    try std.testing.expectEqual(@as(u32, 42), dec.data_length);
}
