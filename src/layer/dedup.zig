//! Dedup group token wired to `broadcast_types.DedupCancel` (aligned with ethp2p session dedup hooks).

const std = @import("std");
const broadcast_types = @import("broadcast_types.zig");
const rs_init = @import("rs_init.zig");
const rs_strategy = @import("rs_strategy.zig");

/// Fires when `DedupCancel.cancel` runs after a successful `takeChunk` (or any caller that invokes cancel).
pub const DedupGroup = struct {
    fired: bool = false,

    pub const Token = struct {
        cancel: broadcast_types.DedupCancel = .{ .cancel_impl = Token.onCancel },
        group: *DedupGroup,

        fn onCancel(d: *broadcast_types.DedupCancel) void {
            const tok: *Token = @alignCast(@fieldParentPtr("cancel", d));
            tok.group.fired = true;
        }

        pub fn dedupPtr(self: *Token) *broadcast_types.DedupCancel {
            return &self.cancel;
        }
    };

    pub fn token(self: *DedupGroup) Token {
        return .{ .group = self };
    }
};

test "dedup cancel marks group after takeChunk accepts" {
    const gpa = std.testing.allocator;
    const peer = "p";
    var stats: broadcast_types.PeerSessionStats = .{ .peer_id = peer };

    const cfg = rs_init.RsConfig{
        .data_shards = 4,
        .parity_shards = 2,
        .chunk_len = 0,
        .bitmap_threshold = 0,
        .forward_multiplier = 4,
        .disable_bitmap = false,
    };

    const msg = [_]u8{ 1, 2, 3, 4, 5 };
    var origin = try rs_strategy.RsStrategy.newOrigin(gpa, cfg, &msg);
    defer origin.deinit();

    var relay = try rs_strategy.RsStrategy.newRelay(gpa, cfg, &origin.preamble);
    defer relay.deinit();
    try relay.attachPeer(peer, &stats);

    var group: DedupGroup = .{};
    var tok = group.token();

    const r = try relay.takeChunk(peer, .{ .index = 0 }, origin.chunks[0], tok.dedupPtr());
    try std.testing.expectEqual(broadcast_types.Verdict.accepted, r.verdict);
    try std.testing.expect(group.fired);
}
