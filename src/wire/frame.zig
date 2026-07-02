const std = @import("std");

/// Matches `broadcast.MaxFrameSize` in the reference Go implementation.
pub const max_frame_size: u32 = 1 << 20;

pub const FrameError = error{
    FrameTooLarge,
};

/// Writes a length-prefixed payload: 4-byte big-endian length then bytes.
/// Matches `broadcast.WriteFrame` in github.com/ethp2p/ethp2p.
pub fn writeFrame(writer: *std.Io.Writer, payload: []const u8) (std.Io.Writer.Error || FrameError)!void {
    if (payload.len > max_frame_size) return error.FrameTooLarge;
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(payload.len), .big);
    try writer.writeAll(&len_buf);
    try writer.writeAll(payload);
}

/// Reads one frame into memory allocated with `allocator`. Caller owns the returned slice.
pub fn readFrame(allocator: std.mem.Allocator, reader: *std.Io.Reader) ![]u8 {
    var len_buf: [4]u8 = undefined;
    try reader.readSliceAll(&len_buf);
    const length = std.mem.readInt(u32, &len_buf, .big);
    if (length > max_frame_size) return error.FrameTooLarge;
    const data = try allocator.alloc(u8, length);
    errdefer allocator.free(data);
    try reader.readSliceAll(data);
    return data;
}

test "writeFrame readFrame roundtrip" {
    const alloc = std.testing.allocator;
    var aw = std.Io.Writer.Allocating.init(alloc);
    defer aw.deinit();

    const payload = "hello ethp2p";
    {
        try writeFrame(&aw.writer, payload);
    }

    var stream = std.Io.Reader.fixed(aw.written());
    const out = try readFrame(alloc, &stream);
    defer alloc.free(out);
    try std.testing.expectEqualStrings(payload, out);
}

test "framed payload preserves reference bcast handshake bytes" {
    const alloc = std.testing.allocator;
    var inner_buf: [32]u8 = undefined;
    const inner = try std.fmt.hexToBytes(&inner_buf, "0a1708011206626c6f636b731204617474731a057065657231");

    var aw = std.Io.Writer.Allocating.init(alloc);
    defer aw.deinit();
    {
        try writeFrame(&aw.writer, inner);
    }

    var stream = std.Io.Reader.fixed(aw.written());
    const round = try readFrame(alloc, &stream);
    defer alloc.free(round);
    try std.testing.expectEqualSlices(u8, inner, round);
}
