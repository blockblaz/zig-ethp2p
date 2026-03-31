//! Per-message RS session: wraps `layer.rs_strategy.RsStrategy` for one broadcast message.

const std = @import("std");
const broadcast_types = @import("../layer/broadcast_types.zig");
const rs_strategy = @import("../layer/rs_strategy.zig");

const Allocator = std.mem.Allocator;
const RsStrategy = rs_strategy.RsStrategy;

pub const SessionRs = struct {
    allocator: Allocator,
    /// Owned by the parent `ChannelRs` map key; not freed here.
    message_id: []const u8,
    strategy: RsStrategy,
    member_ids: [][]u8,
    stats: []broadcast_types.PeerSessionStats,

    pub fn deinit(self: *SessionRs) void {
        self.strategy.deinit();
        for (self.member_ids) |m| self.allocator.free(m);
        self.allocator.free(self.member_ids);
        self.allocator.free(self.stats);
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
};
