const std = @import("std");
const broadcast = @import("broadcast.zig");
const frame = @import("frame.zig");
const protocol = @import("protocol.zig");

pub const SessStreamError = error{ExpectedSessionOpen};

/// Writes one length-prefixed `Sess` frame (no selector). Matches
/// `WriteFrame` on an outbound SESS stream after the opener.
pub fn writeSessFrame(writer: anytype, allocator: std.mem.Allocator, msg: broadcast.Sess) !void {
    const bytes = try broadcast.encodeSess(allocator, msg);
    defer allocator.free(bytes);
    try frame.writeFrame(writer, bytes);
}

/// Reads one `Sess` frame. Used for both the first open and subsequent routing updates.
pub fn readSessFrame(allocator: std.mem.Allocator, reader: anytype) !broadcast.SessOwned {
    const bytes = try frame.readFrame(allocator, reader);
    defer allocator.free(bytes);
    return broadcast.decodeSess(allocator, bytes);
}

/// Opens an outbound SESS stream: selector `PROTOCOL_SESS` then `session_open`.
/// Matches `PeerConn.handleSessionOpen` (`peer_ctrl.go`).
pub fn writeSessSessionOpen(writer: anytype, allocator: std.mem.Allocator, open: broadcast.SessOpen) !void {
    try protocol.writeSelectorByte(writer, .sess);
    try writeSessFrame(writer, allocator, .{ .session_open = open });
}

/// After `PROTOCOL_SESS` was read (e.g. in an accept loop), the first frame MUST be
/// `session_open`. Matches `runInboundSession`’s first `ReadFrame` (`peer_in.go`).
pub fn readSessSessionOpenAfterSelector(allocator: std.mem.Allocator, reader: anytype) !broadcast.SessOwned {
    var msg = try readSessFrame(allocator, reader);
    switch (msg) {
        .session_open => return msg,
        else => {
            msg.deinit(allocator);
            return error.ExpectedSessionOpen;
        },
    }
}

test "sess session open matches reference layout" {
    const alloc = std.testing.allocator;
    var golden_buf: [64]u8 = undefined;
    const golden = try std.fmt.hexToBytes(&golden_buf, "02000000150a130a0363683112036d69641a0301020322020405");

    var list = std.ArrayList(u8).empty;
    defer list.deinit(alloc);
    {
        const w = list.writer(alloc);
        try writeSessSessionOpen(w, alloc, .{
            .channel = "ch1",
            .message_id = "mid",
            .preamble = &.{ 1, 2, 3 },
            .initial_update = &.{ 4, 5 },
        });
    }
    try std.testing.expectEqualSlices(u8, golden, list.items);

    var fbs = std.io.fixedBufferStream(list.items);
    const sel = try protocol.readSelectorByte(fbs.reader());
    try std.testing.expectEqual(protocol.Protocol.sess, sel);
    var open = try readSessSessionOpenAfterSelector(alloc, fbs.reader());
    defer open.deinit(alloc);
    switch (open) {
        .session_open => |o| {
            try std.testing.expectEqualStrings("ch1", o.channel);
            try std.testing.expectEqualStrings("mid", o.message_id);
        },
        else => unreachable,
    }
}

test "sess routing update roundtrip after open" {
    const alloc = std.testing.allocator;
    var list = std.ArrayList(u8).empty;
    defer list.deinit(alloc);
    {
        const w = list.writer(alloc);
        try writeSessFrame(w, alloc, .{ .routing_update = .{ .data = &.{ 0xAB, 0xCD } } });
    }
    var fbs = std.io.fixedBufferStream(list.items);
    var upd = try readSessFrame(alloc, fbs.reader());
    defer upd.deinit(alloc);
    switch (upd) {
        .routing_update => |u| try std.testing.expectEqualSlices(u8, &.{ 0xAB, 0xCD }, u.data),
        else => unreachable,
    }
}
