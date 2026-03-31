const std = @import("std");
const broadcast = @import("broadcast.zig");
const frame = @import("frame.zig");
const protocol = @import("protocol.zig");
const rs = @import("rs.zig");

/// Matches `maxChunkDataSize` in `broadcast/peer_in.go`.
pub const max_chunk_data_size: u32 = 1 << 20;

pub const ChunkStreamError = error{
    ChunkPayloadTooLarge,
    NotChunkStream,
};

/// One inbound chunk after the reference has already consumed the stream
/// selector (`PROTOCOL_CHUNK`). Matches `PeerConn.processChunk` after
/// `ReadSelector`: `ReadFrame` for `Chunk_Header`, then `data_length` raw bytes.
pub const ChunkIn = struct {
    header: broadcast.ChunkHeaderOwned,
    payload: []u8,

    pub fn deinit(self: *ChunkIn, allocator: std.mem.Allocator) void {
        self.header.deinit(allocator);
        allocator.free(self.payload);
    }
};

/// Writes a full CHUNK uni stream: selector byte, length-framed protobuf
/// `Chunk.Header`, then raw payload. Matches `PeerConn.doSendChunk`.
pub fn writeChunkStream(
    writer: anytype,
    allocator: std.mem.Allocator,
    channel: []const u8,
    message_id: []const u8,
    chunk_id: []const u8,
    payload: []const u8,
) (@TypeOf(writer).Error || frame.FrameError || std.mem.Allocator.Error || ChunkStreamError)!void {
    if (payload.len > max_chunk_data_size) return error.ChunkPayloadTooLarge;

    try protocol.writeSelectorByte(writer, .chunk);

    const header_pb = try broadcast.encodeChunkHeader(allocator, .{
        .channel = channel,
        .message_id = message_id,
        .chunk_id = chunk_id,
        .data_length = @intCast(payload.len),
    });
    defer allocator.free(header_pb);

    try frame.writeFrame(writer, header_pb);
    try writer.writeAll(payload);
}

/// `Chunk.Header.chunk_id` carries `proto.Marshal(rspb.ChunkIdent{index})`, as in
/// `broadcast/rs/types.go` `ChunkIdent.Marshal`.
pub fn writeRsShardChunk(
    writer: anytype,
    allocator: std.mem.Allocator,
    channel: []const u8,
    message_id: []const u8,
    shard_index: i32,
    payload: []const u8,
) (@TypeOf(writer).Error || frame.FrameError || std.mem.Allocator.Error || ChunkStreamError)!void {
    const chunk_id = try rs.encodeChunkIdent(allocator, .{ .index = shard_index });
    defer allocator.free(chunk_id);
    try writeChunkStream(writer, allocator, channel, message_id, chunk_id, payload);
}

/// Reads selector, header frame, and payload. Caller must `ChunkIn.deinit`.
pub fn readChunkStream(allocator: std.mem.Allocator, reader: anytype) !ChunkIn {
    const sel = try protocol.readSelectorByte(reader);
    if (sel != .chunk) return error.NotChunkStream;
    return readChunkAfterSelector(allocator, reader);
}

/// Reads header frame + payload when `PROTOCOL_CHUNK` was already read.
pub fn readChunkAfterSelector(allocator: std.mem.Allocator, reader: anytype) !ChunkIn {
    const header_pb = try frame.readFrame(allocator, reader);
    errdefer allocator.free(header_pb);

    var header = try broadcast.decodeChunkHeader(allocator, header_pb);
    errdefer header.deinit(allocator);
    allocator.free(header_pb);

    if (header.data_length > max_chunk_data_size) return error.ChunkPayloadTooLarge;

    const payload = try allocator.alloc(u8, header.data_length);
    errdefer allocator.free(payload);
    try reader.readNoEof(payload);

    return .{
        .header = header,
        .payload = payload,
    };
}

test "chunk stream golden matches reference encoder" {
    const alloc = std.testing.allocator;
    var golden_buf: [64]u8 = undefined;
    const golden = try std.fmt.hexToBytes(&golden_buf, "030000000b0a016312016d1a01092002aabb");

    var list = std.ArrayList(u8).empty;
    defer list.deinit(alloc);
    {
        const w = list.writer(alloc);
        try writeChunkStream(w, alloc, "c", "m", &.{9}, &.{ 0xAA, 0xBB });
    }
    try std.testing.expectEqualSlices(u8, golden, list.items);

    var fbs = std.io.fixedBufferStream(list.items);
    var got = try readChunkStream(alloc, fbs.reader());
    defer got.deinit(alloc);
    try std.testing.expectEqualStrings("c", got.header.channel);
    try std.testing.expectEqualStrings("m", got.header.message_id);
    try std.testing.expectEqualSlices(u8, &.{9}, got.header.chunk_id);
    try std.testing.expectEqual(@as(u32, 2), got.header.data_length);
    try std.testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB }, got.payload);
}

test "rs shard chunk stream matches reference (ChunkIdent in header)" {
    const alloc = std.testing.allocator;
    var golden_buf: [64]u8 = undefined;
    const golden = try std.fmt.hexToBytes(&golden_buf, "030000000c0a016312016d1a0208072001ff");

    var list = std.ArrayList(u8).empty;
    defer list.deinit(alloc);
    {
        const w = list.writer(alloc);
        try writeRsShardChunk(w, alloc, "c", "m", 7, &.{0xFF});
    }
    try std.testing.expectEqualSlices(u8, golden, list.items);

    var fbs = std.io.fixedBufferStream(list.items);
    var got = try readChunkStream(alloc, fbs.reader());
    defer got.deinit(alloc);
    const ident = try rs.decodeChunkIdent(alloc, got.header.chunk_id);
    try std.testing.expectEqual(@as(i32, 7), ident.index);
}

test "readChunkAfterSelector matches processChunk framing" {
    const alloc = std.testing.allocator;
    // After selector 0x03: framed header + payload only
    var golden_buf: [64]u8 = undefined;
    const after_sel = try std.fmt.hexToBytes(&golden_buf, "0000000b0a016312016d1a01092002aabb");
    var fbs = std.io.fixedBufferStream(after_sel);
    var got = try readChunkAfterSelector(alloc, fbs.reader());
    defer got.deinit(alloc);
    try std.testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB }, got.payload);
}
