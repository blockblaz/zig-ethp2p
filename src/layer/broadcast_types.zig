//! Broadcast-layer enums and aliases aligned with ethp2p `broadcast/types.go`.

const std = @import("std");

pub const ChunkHandle = u64;

pub const protocol_v1: u32 = 1;

pub const Verdict = enum(u8) {
    accepted = 0,
    redundant = 1,
    decoding = 2,
    surplus = 3,
    invalid = 4,
    pending = 5,
};

pub const ChunkIngestResult = struct {
    verdict: Verdict,
    complete: bool,
};

/// Session passes this into `RsStrategy.takeChunk` so the strategy can cancel the dedup group.
/// Nil-safe: `cancel(null)` is a no-op.
pub const DedupCancel = struct {
    cancel_impl: ?*const fn (*DedupCancel) void = null,

    pub fn cancel(self: ?*DedupCancel) void {
        if (self) |d| {
            if (d.cancel_impl) |f| f(d);
        }
    }
};

/// Per-peer per-session stats; the session owns and mutates fields. Strategy holds a pointer only.
pub const PeerSessionStats = struct {
    peer_id: []const u8 = &.{},
    /// Measured RTT in ms; `maxInt(u32)` means unknown (lowest dispatch preference).
    rtt_ms: u32 = std.math.maxInt(u32),
};

pub fn ChunkDispatch(comptime ChunkId: type) type {
    return struct {
        peer: []const u8,
        chunk_id: ChunkId,
        data: []const u8,
    };
}
