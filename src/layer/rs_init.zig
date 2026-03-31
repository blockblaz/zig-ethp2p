//! RS `Config` and `initPreamble` from ethp2p `broadcast/rs/types.go`.

const std = @import("std");

pub const RsConfig = struct {
    data_shards: u32,
    parity_shards: u32,
    /// Zero means derive chunk length from message length and shard counts.
    chunk_len: u32,
    bitmap_threshold: i32,
    forward_multiplier: i32,
    disable_bitmap: bool,

    pub fn default() RsConfig {
        return .{
            .data_shards = 16,
            .parity_shards = 16,
            .chunk_len = 0,
            .bitmap_threshold = 50,
            .forward_multiplier = 4,
            .disable_bitmap = false,
        };
    }
};

fn divCeilInt(a: usize, b: usize) usize {
    return (a + b - 1) / b;
}

pub const PreambleLayout = struct {
    data_chunks: i32,
    parity_chunks: i32,
    message_length: i32,
    chunk_len: usize,
};

/// Mirrors `initPreamble` in the reference: derives data/parity counts and per-shard length.
pub fn initPreamble(cfg: RsConfig, msg_len: usize) PreambleLayout {
    var chunk_len: usize = if (cfg.chunk_len == 0) 0 else @intCast(cfg.chunk_len);
    var data_chunks: i32 = undefined;
    var parity_chunks: i32 = undefined;

    if (cfg.chunk_len == 0) {
        data_chunks = @intCast(cfg.data_shards);
        parity_chunks = @intCast(cfg.parity_shards);
        chunk_len = divCeilInt(msg_len, @as(usize, @intCast(data_chunks)));
        const total_chunks: i32 = data_chunks + parity_chunks;
        if (total_chunks >= 256) {
            const rem = chunk_len % 64;
            if (rem != 0) chunk_len += 64 - rem;
        }
    } else {
        data_chunks = @intCast(divCeilInt(msg_len, chunk_len));
        parity_chunks = data_chunks;
    }

    return .{
        .data_chunks = data_chunks,
        .parity_chunks = parity_chunks,
        .message_length = @intCast(msg_len),
        .chunk_len = chunk_len,
    };
}

test "initPreamble fixed chunk len" {
    const cfg = RsConfig{
        .data_shards = 0,
        .parity_shards = 0,
        .chunk_len = 100,
        .bitmap_threshold = 0,
        .forward_multiplier = 0,
        .disable_bitmap = false,
    };
    const p = initPreamble(cfg, 250);
    try std.testing.expectEqual(@as(i32, 3), p.data_chunks);
    try std.testing.expectEqual(@as(i32, 3), p.parity_chunks);
    try std.testing.expectEqual(@as(i32, 250), p.message_length);
    try std.testing.expectEqual(@as(usize, 100), p.chunk_len);
}

test "initPreamble derived chunk len" {
    const cfg = RsConfig{
        .data_shards = 4,
        .parity_shards = 2,
        .chunk_len = 0,
        .bitmap_threshold = 0,
        .forward_multiplier = 0,
        .disable_bitmap = false,
    };
    const p = initPreamble(cfg, 10);
    try std.testing.expectEqual(@as(i32, 4), p.data_chunks);
    try std.testing.expectEqual(@as(i32, 2), p.parity_chunks);
    try std.testing.expectEqual(@as(usize, 3), p.chunk_len);
}
