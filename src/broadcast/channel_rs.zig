//! RS-only broadcast channel: members, sessions, publish (aligned with ethp2p `broadcast/channel.go`).
//! Ingest: `relayIngestChunk` stores bytes without a hash check; `relayIngestChunkVerified` runs
//! `RsStrategy.verifyChunk` first so invalid shards never hit the dedup registry or `takeChunk`.
//! RS `verifyChunk` is synchronous (`.accepted` / `.invalid` only); `.pending` is for other schemes.
//! Async SHA256 + `takeChunk` matches Go `handleVerifyResult` → `acceptChunk` via `broadcast.relay_async_verify`.

const std = @import("std");
const broadcast_types = @import("../layer/broadcast_types.zig");
const dedup_mod = @import("../layer/dedup.zig");
const dedup_registry_mod = @import("../layer/dedup_registry.zig");
const emit_planner = @import("../layer/emit_planner.zig");
const rs_init = @import("../layer/rs_init.zig");
const rs_strategy = @import("../layer/rs_strategy.zig");
const Engine = @import("engine.zig").Engine;
const errors = @import("errors.zig");
const SendRsChunkFn = @import("session_rs.zig").SendRsChunkFn;
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
            .members = .empty,
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
        self.engine.config.observer.peerSubscribed(peer_id, self.id);
    }

    pub fn removeMember(self: *ChannelRs, peer_id: []const u8) void {
        for (self.members.items, 0..) |m, i| {
            if (std.mem.eql(u8, m, peer_id)) {
                self.allocator.free(m);
                _ = self.members.swapRemove(i);
                self.engine.config.observer.peerUnsubscribed(peer_id, self.id);
                return;
            }
        }
    }

    /// Origin session: encodes `payload` and attaches current members.
    pub fn publish(self: *ChannelRs, message_id: []const u8, payload: []const u8) !void {
        if (self.sessions.get(message_id) != null) return error.InvalidMessage;

        const mid = try self.allocator.dupe(u8, message_id);
        errdefer self.allocator.free(mid);

        var strat: ?RsStrategy = try RsStrategy.newOrigin(self.allocator, self.cfg, payload);
        errdefer if (strat) |*s| s.deinit();

        const n = self.members.items.len;
        const member_ids = try self.allocator.alloc([]u8, n);
        var populated: usize = 0;
        errdefer {
            for (member_ids[0..populated]) |m| self.allocator.free(m);
            self.allocator.free(member_ids);
        }
        const stats = try self.allocator.alloc(broadcast_types.PeerSessionStats, n);
        errdefer self.allocator.free(stats);

        while (populated < n) : (populated += 1) {
            member_ids[populated] = try self.allocator.dupe(u8, self.members.items[populated]);
            stats[populated] = .{ .peer_id = member_ids[populated] };
            try strat.?.attachPeer(member_ids[populated], &stats[populated]);
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
        self.engine.config.observer.sessionStarted(self.id, mid, .origin);
    }

    /// Relay-side session for an existing preamble (same members as `publish`).
    pub fn attachRelaySession(self: *ChannelRs, message_id: []const u8, preamble: *const rs_strategy.RsPreamble) !void {
        if (self.sessions.get(message_id) != null) return error.InvalidMessage;

        const mid = try self.allocator.dupe(u8, message_id);
        errdefer self.allocator.free(mid);

        var strat = try RsStrategy.newRelay(self.allocator, self.cfg, preamble);
        errdefer strat.deinit();

        const n = self.members.items.len;
        const member_ids = try self.allocator.alloc([]u8, n);
        var populated: usize = 0;
        errdefer {
            for (member_ids[0..populated]) |m| self.allocator.free(m);
            self.allocator.free(member_ids);
        }
        const stats = try self.allocator.alloc(broadcast_types.PeerSessionStats, n);
        errdefer self.allocator.free(stats);

        while (populated < n) : (populated += 1) {
            member_ids[populated] = try self.allocator.dupe(u8, self.members.items[populated]);
            stats[populated] = .{ .peer_id = member_ids[populated] };
            try strat.attachPeer(member_ids[populated], &stats[populated]);
        }

        const sess = try self.allocator.create(SessionRs);
        errdefer {
            sess.deinit();
            self.allocator.destroy(sess);
        }
        sess.* = .{
            .allocator = self.allocator,
            .message_id = mid,
            .strategy = strat,
            .member_ids = member_ids,
            .stats = stats,
        };

        try self.sessions.put(self.allocator, mid, sess);
        self.engine.config.observer.sessionStarted(self.id, mid, .relay);
    }

    pub fn sessionDrainOutbound(self: *ChannelRs, message_id: []const u8) !usize {
        const slot = self.sessions.getPtr(message_id) orelse return error.InvalidMessage;
        return slot.*.drainOutbound();
    }

    /// Same as [`SessionRs.drainOutboundOverQuic`](`SessionRs.drainOutboundOverQuic`) for `message_id` on this channel.
    pub fn sessionDrainOutboundOverQuic(
        self: *ChannelRs,
        message_id: []const u8,
        ctx: *anyopaque,
        send_chunk: SendRsChunkFn,
    ) (Allocator.Error || emit_planner.PlannerError || anyerror)!usize {
        const slot = self.sessions.getPtr(message_id) orelse return error.InvalidMessage;
        return slot.*.drainOutboundOverQuic(self.id, ctx, send_chunk);
    }

    pub fn sessionDecode(self: *ChannelRs, message_id: []const u8) ![]u8 {
        const slot = self.sessions.getPtr(message_id) orelse return error.InvalidMessage;
        const out = try slot.*.strategy.decode();
        // Latency is not tracked in the Zig port yet (no per-session start clock);
        // emit 0 for now — Go passes `time.Since(session.start)`.
        self.engine.config.observer.sessionDecoded(self.id, message_id, 0);
        return out;
    }

    /// After a successful decode, clears engine `DedupRegistry` keys for this `(channel_id, message_id)`
    /// when `EngineConfig.enable_cross_session_dedup` is set (no-op otherwise).
    pub fn sessionDecodeClearEngineDedup(self: *ChannelRs, message_id: []const u8) ![]u8 {
        const out = try self.sessionDecode(message_id);
        if (self.engine.dedupRegistryPtr() != null) {
            self.engine.forgetDedupForMessage(self.id, message_id);
        }
        return out;
    }

    pub fn sessionStrategy(self: *ChannelRs, message_id: []const u8) ?*RsStrategy {
        const slot = self.sessions.getPtr(message_id) orelse return null;
        return &slot.*.strategy;
    }

    /// Ingest a relay chunk: optional cross-session dedup, then `takeChunk`.
    pub fn relayIngestChunk(
        self: *ChannelRs,
        registry: ?*dedup_registry_mod.DedupRegistry,
        message_id: []const u8,
        peer: []const u8,
        chunk_id: rs_strategy.ChunkIdent,
        data: []const u8,
        dedup: ?*broadcast_types.DedupCancel,
    ) (Allocator.Error || errors.Error)!broadcast_types.ChunkIngestResult {
        const strat = self.sessionStrategy(message_id) orelse return error.InvalidMessage;
        const result: broadcast_types.ChunkIngestResult = blk: {
            if (registry) |reg| {
                const first = try reg.claim(self.allocator, self.id, message_id, chunk_id.index);
                if (!first) break :blk .{ .verdict = .redundant, .complete = false };
            }
            break :blk try strat.takeChunk(peer, chunk_id, data, dedup);
        };
        self.engine.config.observer.chunkRcvd(peer, self.id, message_id, result.verdict);
        return result;
    }

    /// `relayIngestChunk` using the engine-owned registry when cross-session dedup is enabled; otherwise `null`.
    pub fn relayIngestChunkEngine(
        self: *ChannelRs,
        message_id: []const u8,
        peer: []const u8,
        chunk_id: rs_strategy.ChunkIdent,
        data: []const u8,
        dedup: ?*broadcast_types.DedupCancel,
    ) (Allocator.Error || errors.Error)!broadcast_types.ChunkIngestResult {
        return self.relayIngestChunk(self.engine.dedupRegistryPtr(), message_id, peer, chunk_id, data, dedup);
    }

    /// Like `relayIngestChunk`, but rejects data that fails `verifyChunk` before dedup / `takeChunk`.
    pub fn relayIngestChunkVerified(
        self: *ChannelRs,
        registry: ?*dedup_registry_mod.DedupRegistry,
        message_id: []const u8,
        peer: []const u8,
        chunk_id: rs_strategy.ChunkIdent,
        data: []const u8,
        dedup: ?*broadcast_types.DedupCancel,
    ) (Allocator.Error || errors.Error)!broadcast_types.ChunkIngestResult {
        const strat = self.sessionStrategy(message_id) orelse return error.InvalidMessage;
        const v = strat.verifyChunk(chunk_id, data);
        if (v != .accepted) {
            self.engine.config.observer.chunkRcvd(peer, self.id, message_id, v);
            return .{ .verdict = v, .complete = false };
        }
        return self.relayIngestChunk(registry, message_id, peer, chunk_id, data, dedup);
    }

    /// `relayIngestChunkVerified` with `engine.dedupRegistryPtr()` (see `relayIngestChunkEngine`).
    pub fn relayIngestChunkVerifiedEngine(
        self: *ChannelRs,
        message_id: []const u8,
        peer: []const u8,
        chunk_id: rs_strategy.ChunkIdent,
        data: []const u8,
        dedup: ?*broadcast_types.DedupCancel,
    ) (Allocator.Error || errors.Error)!broadcast_types.ChunkIngestResult {
        return self.relayIngestChunkVerified(self.engine.dedupRegistryPtr(), message_id, peer, chunk_id, data, dedup);
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

test "observer receives channel/peer/session events" {
    const gpa = std.testing.allocator;
    var rec: @import("observer.zig").Recording = .{};

    var eng = try Engine.init(gpa, "local", .{ .observer = rec.observer() });
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
    const decoded = try ch.sessionDecode("m1");
    defer gpa.free(decoded);

    try std.testing.expectEqual(@as(usize, 1), rec.channel_attached);
    try std.testing.expectEqual(@as(usize, 1), rec.peer_subscribed);
    try std.testing.expectEqual(@as(usize, 1), rec.session_started);
    try std.testing.expectEqual(@import("../layer/broadcast_types.zig").SessionRole.origin, rec.last_role.?);
    try std.testing.expectEqual(@as(usize, 1), rec.session_decoded);
}

test "relay ingest registry blocks second claim same chunk index" {
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
    try ch.addMember("peerA");
    try ch.addMember("peerB");

    const payload = [_]u8{ 9, 8, 7 };
    var origin = try RsStrategy.newOrigin(gpa, cfg, &payload);
    defer origin.deinit();

    try ch.attachRelaySession("m1", &origin.preamble);

    var reg: dedup_registry_mod.DedupRegistry = .{};
    defer reg.deinit(gpa);

    const chunk0 = origin.chunks[0];

    var ga: dedup_mod.DedupGroup = .{};
    var ta = ga.token();
    const r1 = try ch.relayIngestChunk(&reg, "m1", "peerA", .{ .index = 0 }, chunk0, ta.dedupPtr());
    try std.testing.expectEqual(broadcast_types.Verdict.accepted, r1.verdict);
    try std.testing.expect(ga.fired);

    const r2 = try ch.relayIngestChunk(&reg, "m1", "peerB", .{ .index = 0 }, chunk0, null);
    try std.testing.expectEqual(broadcast_types.Verdict.redundant, r2.verdict);
}

test "relayIngestChunk unknown message" {
    const gpa = std.testing.allocator;
    var eng = try Engine.init(gpa, "local", .{ .enable_cross_session_dedup = true });
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
    try std.testing.expectError(
        error.InvalidMessage,
        ch.relayIngestChunk(eng.dedupRegistryPtr(), "missing", "peer", .{ .index = 0 }, &.{}, null),
    );
}

test "relayIngestChunkVerified rejects invalid chunk before dedup claim" {
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
    try ch.addMember("peerA");

    const payload = [_]u8{ 9, 8, 7 };
    var origin = try RsStrategy.newOrigin(gpa, cfg, &payload);
    defer origin.deinit();

    try ch.attachRelaySession("m1", &origin.preamble);

    var reg: dedup_registry_mod.DedupRegistry = .{};
    defer reg.deinit(gpa);

    const chunk0 = origin.chunks[0];
    var bad = try gpa.dupe(u8, chunk0);
    defer gpa.free(bad);
    if (bad.len > 0) bad[0] +%= 1;

    const r_bad = try ch.relayIngestChunkVerified(&reg, "m1", "peerA", .{ .index = 0 }, bad, null);
    try std.testing.expectEqual(broadcast_types.Verdict.invalid, r_bad.verdict);

    const r_ok = try ch.relayIngestChunkVerified(&reg, "m1", "peerA", .{ .index = 0 }, chunk0, null);
    try std.testing.expectEqual(broadcast_types.Verdict.accepted, r_ok.verdict);
}

test "engine forgetDedupForMessage clears keys" {
    const gpa = std.testing.allocator;
    var eng = try Engine.init(gpa, "local", .{ .enable_cross_session_dedup = true });
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
    const reg = eng.dedupRegistryPtr().?;
    try std.testing.expect(try reg.claim(gpa, ch.id, "m1", 0));
    eng.forgetDedupForMessage(ch.id, "m1");
    try std.testing.expect(try reg.claim(gpa, ch.id, "m1", 0));
}
