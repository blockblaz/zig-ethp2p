//! RS-only broadcast channel: members, sessions, publish (aligned with ethp2p `broadcast/channel.go`).

const std = @import("std");
const broadcast_types = @import("../layer/broadcast_types.zig");
const rs_init = @import("../layer/rs_init.zig");
const rs_strategy = @import("../layer/rs_strategy.zig");
const Engine = @import("engine.zig").Engine;
const SessionRs = @import("session_rs.zig").SessionRs;

const Allocator = std.mem.Allocator;
const RsConfig = rs_init.RsConfig;
const RsStrategy = rs_strategy.RsStrategy;

pub const ChannelRs = struct {
    allocator: Allocator,
    engine: *Engine,
    id: []u8,
    cfg: RsConfig,
    members: std.ArrayListUnmanaged([]u8),
    sessions: std.StringHashMapUnmanaged(*SessionRs),

    pub fn init(allocator: Allocator, engine: *Engine, id: []u8, cfg: RsConfig) !ChannelRs {
        return .{
            .allocator = allocator,
            .engine = engine,
            .id = id,
            .cfg = cfg,
            .members = .{},
            .sessions = .{},
        };
    }

    pub fn deinit(self: *ChannelRs) void {
        var sit = self.sessions.iterator();
        while (sit.next()) |kv| {
            const sess = kv.value_ptr.*;
            sess.deinit();
            self.allocator.destroy(sess);
            self.allocator.free(kv.key_ptr.*);
        }
        self.sessions.deinit(self.allocator);
        for (self.members.items) |m| self.allocator.free(m);
        self.members.deinit(self.allocator);
        self.allocator.free(self.id);
    }

    pub fn addMember(self: *ChannelRs, peer_id: []const u8) !void {
        for (self.members.items) |m| {
            if (std.mem.eql(u8, m, peer_id)) return;
        }
        const dup = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(dup);
        try self.members.append(self.allocator, dup);
    }

    pub fn removeMember(self: *ChannelRs, peer_id: []const u8) void {
        for (self.members.items, 0..) |m, i| {
            if (std.mem.eql(u8, m, peer_id)) {
                self.allocator.free(m);
                _ = self.members.swapRemove(i);
                return;
            }
        }
    }

    /// Origin session: encodes `payload` and attaches current members.
    pub fn publish(self: *ChannelRs, message_id: []const u8, payload: []const u8) !void {
        if (self.sessions.get(message_id) != null) return error.DuplicateMessage;

        const mid = try self.allocator.dupe(u8, message_id);
        errdefer self.allocator.free(mid);

        var strat: ?RsStrategy = try RsStrategy.newOrigin(self.allocator, self.cfg, payload);
        errdefer if (strat) |*s| s.deinit();

        const n = self.members.items.len;
        const member_ids = try self.allocator.alloc([]u8, n);
        errdefer {
            for (member_ids) |m| self.allocator.free(m);
            self.allocator.free(member_ids);
        }
        const stats = try self.allocator.alloc(broadcast_types.PeerSessionStats, n);
        errdefer self.allocator.free(stats);

        for (0..n) |i| {
            member_ids[i] = try self.allocator.dupe(u8, self.members.items[i]);
            stats[i] = .{ .peer_id = member_ids[i] };
            try strat.?.attachPeer(member_ids[i], &stats[i]);
        }

        const sess = try self.allocator.create(SessionRs);
        errdefer {
            sess.deinit();
            self.allocator.destroy(sess);
        }
        sess.* = .{
            .allocator = self.allocator,
            .message_id = mid,
            .strategy = strat.?,
            .member_ids = member_ids,
            .stats = stats,
        };
        strat = null;

        try self.sessions.put(self.allocator, mid, sess);
    }

    pub fn sessionDrainOutbound(self: *ChannelRs, message_id: []const u8) !usize {
        const slot = self.sessions.getPtr(message_id) orelse return error.UnknownMessage;
        return slot.*.drainOutbound();
    }

    pub fn sessionDecode(self: *ChannelRs, message_id: []const u8) ![]u8 {
        const slot = self.sessions.getPtr(message_id) orelse return error.UnknownMessage;
        return slot.*.strategy.decode();
    }

    pub fn sessionStrategy(self: *ChannelRs, message_id: []const u8) ?*RsStrategy {
        const slot = self.sessions.getPtr(message_id) orelse return null;
        return &slot.*.strategy;
    }
};

test "channel publish and drain to one member" {
    const gpa = std.testing.allocator;
    var eng = try Engine.init(gpa, "local", .{});
    defer eng.deinit();

    const cfg = RsConfig{
        .data_shards = 4,
        .parity_shards = 2,
        .chunk_len = 0,
        .bitmap_threshold = 0,
        .forward_multiplier = 4,
        .disable_bitmap = false,
    };

    const ch = try eng.attachChannelRs("topic", cfg);
    try ch.addMember("p1");

    const payload = [_]u8{ 'h', 'e', 'l', 'l', 'o' };
    try ch.publish("m1", &payload);

    const n = try ch.sessionDrainOutbound("m1");
    try std.testing.expect(n > 0);

    const decoded = try ch.sessionDecode("m1");
    defer gpa.free(decoded);
    try std.testing.expectEqualSlices(u8, &payload, decoded);
}
