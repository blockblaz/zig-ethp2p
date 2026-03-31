const std = @import("std");
const broadcast = @import("broadcast.zig");
const frame = @import("frame.zig");
const protocol = @import("protocol.zig");

pub const BcastStreamError = error{
    WrongBcastStream,
    ExpectedPeerHandshake,
};

/// Writes one length-prefixed `Bcast` frame (no selector). Matches
/// `PeerConn.writeCtrl` / `WriteFrame` on `ctrlOut`.
pub fn writeBcastCtrlFrame(writer: anytype, allocator: std.mem.Allocator, msg: broadcast.Bcast) !void {
    const bytes = try broadcast.encodeBcast(allocator, msg);
    defer allocator.free(bytes);
    try frame.writeFrame(writer, bytes);
}

/// Reads one `Bcast` frame. Matches `runCtrlReader`’s `ReadFrame` loop on `ctrlIn`
/// (after the peer’s stream was accepted and the selector was validated elsewhere).
pub fn readBcastCtrlFrame(allocator: std.mem.Allocator, reader: anytype) !broadcast.BcastOwned {
    const bytes = try frame.readFrame(allocator, reader);
    defer allocator.free(bytes);
    return broadcast.decodeBcast(allocator, bytes);
}

/// Outbound BCAST stream start: selector `PROTOCOL_BCAST` then handshake frame.
/// Matches the writer side of `PeerConn.handshake` (`peer.go`).
pub fn writeBcastHandshakeOpen(writer: anytype, allocator: std.mem.Allocator, hs: broadcast.Handshake) !void {
    try protocol.writeSelectorByte(writer, .bcast);
    try writeBcastCtrlFrame(writer, allocator, .{ .peer_handshake = hs });
}

/// Inbound BCAST stream: read selector, then first frame must be `peer_handshake`.
/// Matches the reader side of `PeerConn.handshake`.
pub fn readBcastPeerHandshake(allocator: std.mem.Allocator, reader: anytype) !broadcast.BcastOwned {
    const sel = try protocol.readSelectorByte(reader);
    if (sel != .bcast) return error.WrongBcastStream;
    var msg = try readBcastCtrlFrame(allocator, reader);
    switch (msg) {
        .peer_handshake => return msg,
        else => {
            msg.deinit(allocator);
            return error.ExpectedPeerHandshake;
        },
    }
}

test "bcast handshake open matches reference layout" {
    const alloc = std.testing.allocator;
    var golden_buf: [64]u8 = undefined;
    const golden = try std.fmt.hexToBytes(&golden_buf, "01000000190a1708011206626c6f636b731204617474731a057065657231");

    var list = std.ArrayList(u8).empty;
    defer list.deinit(alloc);
    {
        const w = list.writer(alloc);
        try writeBcastHandshakeOpen(w, alloc, .{
            .version = 1,
            .channels = &.{ "blocks", "atts" },
            .peer_id = "peer1",
        });
    }
    try std.testing.expectEqualSlices(u8, golden, list.items);

    var fbs = std.io.fixedBufferStream(list.items);
    var hs = try readBcastPeerHandshake(alloc, fbs.reader());
    defer hs.deinit(alloc);
    switch (hs) {
        .peer_handshake => |h| {
            try std.testing.expectEqual(@as(u32, 1), h.version);
            try std.testing.expectEqualStrings("peer1", h.peer_id);
        },
        else => unreachable,
    }
}
