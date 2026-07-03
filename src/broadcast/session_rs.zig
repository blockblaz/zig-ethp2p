//! Per-message RS session: wraps `layer.rs_strategy.RsStrategy` for one broadcast message.

const std = @import("std");
const broadcast_types = @import("../layer/broadcast_types.zig");
const emit_planner = @import("../layer/emit_planner.zig");
const rs_strategy = @import("../layer/rs_strategy.zig");

const Allocator = std.mem.Allocator;
const RsStrategy = rs_strategy.RsStrategy;

/// Context + `peerSendRsChunk` (or custom transport) for [`drainOutboundOverQuic`](SessionRs.drainOutboundOverQuic).
pub const SendRsChunkFn = *const fn (
    ctx: *anyopaque,
    channel_id: []const u8,
    message_id: []const u8,
    shard_index: i32,
    payload: []const u8,
) anyerror!void;

/// QUIC application error code a peer's SESS stream is reset with once the
/// session is reconstructed, telling the remote to stop sending chunks.
/// Mirrors ethp2p `sessCodeReconstructed` (`broadcast/peer_in.go`).
pub const sess_code_reconstructed: u64 = 0x01;

/// Linear session lifecycle (ethp2p `sessionStage`). Ordering is meaningful:
/// `stage >= .reconstructed` means "decoded" (a relay that reconstructed, or an
/// origin that always had the payload — `.origin` sorts highest).
pub const SessionStage = enum(u8) {
    consuming = 0, // relay, accepting chunks
    decoding = 1, // relay, decode running
    reconstructed = 2, // relay, decode succeeded
    origin = 3, // origin, has the payload from the start

    /// Whether the session holds the full message (origin or reconstructed relay).
    pub fn isDecoded(self: SessionStage) bool {
        return @intFromEnum(self) >= @intFromEnum(SessionStage.reconstructed);
    }
};

pub const SessionRs = struct {
    allocator: Allocator,
    /// Owned by the parent `ChannelRs` map key; not freed here.
    message_id: []const u8,
    strategy: RsStrategy,
    member_ids: [][]u8,
    stats: []broadcast_types.PeerSessionStats,
    stage: SessionStage = .consuming,
    /// Per-member flags, parallel to `member_ids` (Go tracks these in `peers`).
    completed: []bool = &.{},
    dropped: []bool = &.{},
    /// Whether any peer was ever attached (Go `everHadPeers`); disposal is
    /// gated on this so peerless sessions are left for TTL cleanup.
    ever_had_peers: bool = false,
    /// Creation time in ms (Go `createdAt`), set by the driver that owns the
    /// clock; `0` means "unset" and is skipped by TTL cleanup.
    created_at_ms: i64 = 0,

    pub fn deinit(self: *SessionRs) void {
        self.strategy.deinit();
        for (self.member_ids) |m| self.allocator.free(m);
        self.allocator.free(self.member_ids);
        self.allocator.free(self.stats);
        self.allocator.free(self.completed);
        self.allocator.free(self.dropped);
    }

    /// Mark the session reconstructed after a successful decode
    /// (ethp2p `signalReconstructed`). No-op for origin sessions.
    pub fn signalReconstructed(self: *SessionRs) void {
        if (self.stage == .origin) return;
        self.stage = .reconstructed;
    }

    fn peerIndex(self: *const SessionRs, peer_id: []const u8) ?usize {
        for (self.member_ids, 0..) |m, i| {
            if (std.mem.eql(u8, m, peer_id)) return i;
        }
        return null;
    }

    /// Mark a peer as having completed this session (ethp2p `handlePeerCompleted`).
    pub fn markPeerCompleted(self: *SessionRs, peer_id: []const u8) void {
        if (self.peerIndex(peer_id)) |i| self.completed[i] = true;
    }

    /// Mark a peer as dropped (disconnected). Dropped peers are excluded from
    /// disposal accounting (Go removes them from the `peers` map).
    pub fn dropPeer(self: *SessionRs, peer_id: []const u8) void {
        if (self.peerIndex(peer_id)) |i| self.dropped[i] = true;
    }

    /// Whether the session has no remaining work and can be disposed
    /// (ethp2p `maybeDispose`):
    ///   - not decoded: dispose once every peer has been dropped,
    ///   - decoded: dispose once every still-attached peer has completed.
    /// Peerless sessions never auto-dispose (left for TTL cleanup).
    pub fn maybeDispose(self: *const SessionRs) bool {
        if (!self.ever_had_peers) return false;
        if (!self.stage.isDecoded()) {
            for (self.dropped) |d| {
                if (!d) return false; // a live peer still needs chunks from us
            }
            return true;
        }
        for (self.completed, self.dropped) |c, d| {
            if (!d and !c) return false; // an attached peer has not finished
        }
        return true;
    }

    /// One scheduling step: emit dispatches, then mark sends successful (simulates transport ACK).
    pub fn pumpOnce(self: *SessionRs) !usize {
        const out = try self.strategy.pollChunks();
        defer self.allocator.free(out);
        for (out) |disp| {
            self.strategy.chunkSent(disp.peer, disp.chunk_id.handle(), true);
        }
        return out.len;
    }

    /// Run `pumpOnce` until no more chunks are scheduled.
    pub fn drainOutbound(self: *SessionRs) !usize {
        var total: usize = 0;
        while (true) {
            const n = try self.pumpOnce();
            if (n == 0) break;
            total += n;
        }
        return total;
    }

    /// Drain the RS emit planner by sending each scheduled chunk via `send_chunk` (e.g. QUIC UNI per
    /// [`engine_quic.peerSendRsChunk`](`@import("engine_quic.zig").peerSendRsChunk`)), then `chunkSent` with success.
    pub fn drainOutboundOverQuic(
        self: *SessionRs,
        channel_id: []const u8,
        ctx: *anyopaque,
        send_chunk: SendRsChunkFn,
    ) (Allocator.Error || emit_planner.PlannerError || anyerror)!usize {
        var total: usize = 0;
        while (true) {
            const out = try self.strategy.pollChunks();
            defer self.allocator.free(out);
            if (out.len == 0) break;
            for (out) |disp| {
                send_chunk(ctx, channel_id, self.message_id, disp.chunk_id.index, disp.data) catch |err| {
                    self.strategy.chunkSent(disp.peer, disp.chunk_id.handle(), false);
                    return err;
                };
                self.strategy.chunkSent(disp.peer, disp.chunk_id.handle(), true);
                total += 1;
            }
        }
        return total;
    }
};

test "session stage ordering and reconstructed reset code" {
    try std.testing.expectEqual(@as(u64, 0x01), sess_code_reconstructed);
    try std.testing.expect(!SessionStage.consuming.isDecoded());
    try std.testing.expect(!SessionStage.decoding.isDecoded());
    try std.testing.expect(SessionStage.reconstructed.isDecoded());
    try std.testing.expect(SessionStage.origin.isDecoded());
}
