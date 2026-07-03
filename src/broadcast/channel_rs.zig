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

pub const FullMessage = broadcast_types.FullMessage;

/// Bounded FIFO of decoded messages for a channel subscriber. Owns a copy of
/// each delivered message and drops (counting) on overflow — the Zig analog of
/// Go's non-blocking send to a buffered `chan FullMessage`. Caller-created and
/// caller-owned (like the Go channel); `ChannelRs` only holds a pointer.
pub const Subscription = struct {
    allocator: Allocator,
    ring: []FullMessage,
    head: usize = 0,
    len: usize = 0,
    dropped_count: usize = 0,

    /// `capacity` must be > 0 (an unbuffered subscription is rejected by
    /// `ChannelRs.subscribe` with `error.UnbufferedSubscription`).
    pub fn init(allocator: Allocator, cap: usize) Allocator.Error!Subscription {
        return .{ .allocator = allocator, .ring = try allocator.alloc(FullMessage, cap) };
    }

    pub fn deinit(self: *Subscription) void {
        while (self.pop()) |m| freeMessage(self.allocator, m);
        self.allocator.free(self.ring);
        self.* = undefined;
    }

    pub fn capacity(self: *const Subscription) usize {
        return self.ring.len;
    }
    pub fn count(self: *const Subscription) usize {
        return self.len;
    }
    pub fn dropped(self: *const Subscription) usize {
        return self.dropped_count;
    }

    /// Pop the oldest message; ownership transfers to the caller, who frees it
    /// with `Subscription.freeMessage`.
    pub fn pop(self: *Subscription) ?FullMessage {
        if (self.len == 0) return null;
        const m = self.ring[self.head];
        self.head = (self.head + 1) % self.ring.len;
        self.len -= 1;
        return m;
    }

    /// Enqueue an already-owned message; false (ownership retained by caller)
    /// when full.
    fn pushOwned(self: *Subscription, m: FullMessage) bool {
        if (self.len == self.ring.len) return false;
        self.ring[(self.head + self.len) % self.ring.len] = m;
        self.len += 1;
        return true;
    }

    pub fn freeMessage(allocator: Allocator, m: FullMessage) void {
        allocator.free(m.channel_id);
        allocator.free(m.message_id);
        allocator.free(m.data);
    }
};

// Channel capacity / lifetime constants (ethp2p `broadcast/channel.go`).
pub const channel_inbox_cap: usize = 1024;
pub const max_parked_chunks: usize = 32;
pub const active_session_ttl_ms: i64 = 5 * 60 * 1000;
pub const pending_chunk_ttl_ms: i64 = 10 * 1000;
pub const cleanup_interval_ms: i64 = 30 * 1000;
pub const routing_tick_interval_ms: i64 = 25;

/// A chunk buffered because it arrived before its session existed. Owns copies
/// of `peer` and `data`. (Go parks the QUIC stream itself and lets flow control
/// back-pressure the sender; the Zig ingest path already holds the read bytes.)
pub const ParkedChunk = struct {
    peer: []u8,
    chunk_index: i32,
    data: []u8,
    parked_at_ms: i64,
};

const ParkedList = std.ArrayListUnmanaged(ParkedChunk);

pub const ParkResult = enum { parked, dropped_full };

pub const ChannelRs = struct {
    allocator: Allocator,
    engine: *Engine,
    id: []u8,
    cfg: RsConfig,
    members: std.ArrayListUnmanaged([]u8),
    sessions: std.StringHashMapUnmanaged(*SessionRs),
    subscriber: ?*Subscription = null,
    /// Chunks buffered per message id until the session opens (Go `parked`).
    parked: std.StringHashMapUnmanaged(ParkedList) = .empty,

    pub fn init(allocator: Allocator, engine: *Engine, id: []u8, cfg: RsConfig) !ChannelRs {
        return .{
            .allocator = allocator,
            .engine = engine,
            .id = id,
            .cfg = cfg,
            .members = .empty,
            .sessions = .{},
            .subscriber = null,
            .parked = .empty,
        };
    }

    /// Register a subscriber to receive decoded messages. Mirrors
    /// `Channel.Subscribe`: rejects a second subscriber (`AlreadySubscribed`)
    /// or an unbuffered one (`UnbufferedSubscription`).
    pub fn subscribe(self: *ChannelRs, sub: *Subscription) errors.Error!void {
        if (self.subscriber != null) return error.AlreadySubscribed;
        if (sub.capacity() == 0) return error.UnbufferedSubscription;
        self.subscriber = sub;
    }

    /// Deliver a decoded message to the subscriber (if any), copying the bytes
    /// and dropping on overflow. Mirrors Go `deliverMessage` (the paired
    /// `OnSessionDecoded` emit lives in `sessionDecode`).
    fn deliverMessage(self: *ChannelRs, message_id: []const u8, data: []const u8) Allocator.Error!void {
        const sub = self.subscriber orelse return;
        const cid = try self.allocator.dupe(u8, self.id);
        errdefer self.allocator.free(cid);
        const mid = try self.allocator.dupe(u8, message_id);
        errdefer self.allocator.free(mid);
        const payload = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(payload);
        const msg = FullMessage{ .channel_id = cid, .message_id = mid, .data = payload };
        if (!sub.pushOwned(msg)) {
            Subscription.freeMessage(self.allocator, msg);
            sub.dropped_count += 1;
        }
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
        var pit = self.parked.iterator();
        while (pit.next()) |kv| {
            freeParkedList(self.allocator, kv.value_ptr);
            self.allocator.free(kv.key_ptr.*);
        }
        self.parked.deinit(self.allocator);
        for (self.members.items) |m| self.allocator.free(m);
        self.members.deinit(self.allocator);
        self.allocator.free(self.id);
    }

    /// Buffer a chunk that arrived before its session exists (Go `handleChunk`
    /// park path). Per-message cap `max_parked_chunks`; when full, the new chunk
    /// is dropped (`.dropped_full`) — matching Go, which cancels the stream.
    pub fn parkChunk(
        self: *ChannelRs,
        message_id: []const u8,
        peer: []const u8,
        chunk_index: i32,
        data: []const u8,
        now_ms: i64,
    ) Allocator.Error!ParkResult {
        const gop = try self.parked.getOrPut(self.allocator, message_id);
        if (!gop.found_existing) {
            gop.key_ptr.* = self.allocator.dupe(u8, message_id) catch |err| {
                _ = self.parked.remove(message_id);
                return err;
            };
            gop.value_ptr.* = .empty;
        }
        if (gop.value_ptr.items.len >= max_parked_chunks) return .dropped_full;
        const peer_o = try self.allocator.dupe(u8, peer);
        errdefer self.allocator.free(peer_o);
        const data_o = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(data_o);
        try gop.value_ptr.append(self.allocator, .{
            .peer = peer_o,
            .chunk_index = chunk_index,
            .data = data_o,
            .parked_at_ms = now_ms,
        });
        return .parked;
    }

    /// Number of chunks currently parked for `message_id`.
    pub fn parkedCount(self: *const ChannelRs, message_id: []const u8) usize {
        const list = self.parked.getPtr(message_id) orelse return 0;
        return list.items.len;
    }

    /// Replay and free any chunks parked for `message_id` into its now-open
    /// session (Go `handleSessionOpen` flush). Best-effort: ingest errors are
    /// ignored so a bad parked chunk cannot block the rest.
    fn drainParked(self: *ChannelRs, message_id: []const u8) void {
        if (self.parked.fetchRemove(message_id)) |kv| {
            var list = kv.value;
            for (list.items) |pc| {
                _ = self.relayIngestChunk(self.engine.dedupRegistryPtr(), message_id, pc.peer, .{ .index = pc.chunk_index }, pc.data, null) catch {};
                self.allocator.free(pc.peer);
                self.allocator.free(pc.data);
            }
            list.deinit(self.allocator);
            self.allocator.free(kv.key);
        }
    }

    fn dropParked(self: *ChannelRs, message_id: []const u8) void {
        if (self.parked.fetchRemove(message_id)) |kv| {
            var list = kv.value;
            freeParkedList(self.allocator, &list);
            self.allocator.free(kv.key);
        }
    }

    /// Poll-driven GC (Go `cleanup`, run every `cleanup_interval_ms`): dispose
    /// sessions older than `active_session_ttl_ms` and drop parked-chunk buckets
    /// older than `pending_chunk_ttl_ms`. Sessions with `created_at_ms == 0`
    /// (clock unset) are skipped.
    pub fn cleanup(self: *ChannelRs, now_ms: i64) void {
        // Collect expired session ids first (cannot mutate while iterating).
        var expired_sessions: std.ArrayListUnmanaged([]const u8) = .empty;
        defer expired_sessions.deinit(self.allocator);
        var sit = self.sessions.iterator();
        while (sit.next()) |kv| {
            const created = kv.value_ptr.*.created_at_ms;
            if (created != 0 and now_ms - created > active_session_ttl_ms) {
                expired_sessions.append(self.allocator, kv.key_ptr.*) catch continue;
            }
        }
        for (expired_sessions.items) |mid| self.disposeSession(mid, "ttl_expired");

        var expired_parked: std.ArrayListUnmanaged([]const u8) = .empty;
        defer expired_parked.deinit(self.allocator);
        var pit = self.parked.iterator();
        while (pit.next()) |kv| {
            const list = kv.value_ptr;
            if (list.items.len > 0 and now_ms - list.items[0].parked_at_ms > pending_chunk_ttl_ms) {
                expired_parked.append(self.allocator, kv.key_ptr.*) catch continue;
            }
        }
        for (expired_parked.items) |mid| self.dropParked(mid);
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
        const completed = try self.allocator.alloc(bool, n);
        errdefer self.allocator.free(completed);
        @memset(completed, false);
        const dropped = try self.allocator.alloc(bool, n);
        errdefer self.allocator.free(dropped);
        @memset(dropped, false);

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
            .stage = .origin,
            .completed = completed,
            .dropped = dropped,
            .ever_had_peers = n > 0,
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
        const completed = try self.allocator.alloc(bool, n);
        errdefer self.allocator.free(completed);
        @memset(completed, false);
        const dropped = try self.allocator.alloc(bool, n);
        errdefer self.allocator.free(dropped);
        @memset(dropped, false);

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
            .stage = .consuming,
            .completed = completed,
            .dropped = dropped,
            .ever_had_peers = n > 0,
        };

        try self.sessions.put(self.allocator, mid, sess);
        // Flush chunk streams that arrived before this session existed.
        self.drainParked(mid);
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
        errdefer self.allocator.free(out);
        // Relay session reconstructed (no-op for origin); mirrors Go
        // `signalReconstructed` after a successful decode.
        slot.*.signalReconstructed();
        // Latency is not tracked in the Zig port yet (no per-session start clock);
        // emit 0 for now — Go passes `time.Since(session.start)`.
        self.engine.config.observer.sessionDecoded(self.id, message_id, 0);
        try self.deliverMessage(message_id, out);
        return out;
    }

    /// Remove `message_id`'s session and free it, emitting `OnSessionDisposed`.
    /// Mirrors ethp2p `Channel.disposeSession`; no-op if there is no session.
    pub fn disposeSession(self: *ChannelRs, message_id: []const u8, reason: []const u8) void {
        // Drop parked chunks first, while `message_id` is still valid (it may
        // alias the session key we free below).
        self.dropParked(message_id);
        if (self.sessions.fetchRemove(message_id)) |kv| {
            self.engine.config.observer.sessionDisposed(self.id, kv.key, reason);
            kv.value.deinit();
            self.allocator.destroy(kv.value);
            self.allocator.free(kv.key);
        }
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

fn freeParkedList(allocator: Allocator, list: *ParkedList) void {
    for (list.items) |pc| {
        allocator.free(pc.peer);
        allocator.free(pc.data);
    }
    list.deinit(allocator);
}

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

const sub_test_cfg = RsConfig{
    .data_shards = 4,
    .parity_shards = 2,
    .chunk_len = 0,
    .bitmap_threshold = 0,
    .forward_multiplier = 4,
    .disable_bitmap = false,
};

test "subscribe rejects unbuffered and double subscription" {
    const gpa = std.testing.allocator;
    var eng = try Engine.init(gpa, "local", .{});
    defer eng.deinit();
    const ch = try eng.attachChannelRs("topic", sub_test_cfg);

    var unbuffered = try Subscription.init(gpa, 0);
    defer unbuffered.deinit();
    try std.testing.expectError(error.UnbufferedSubscription, ch.subscribe(&unbuffered));

    var sub = try Subscription.init(gpa, 4);
    defer sub.deinit();
    try ch.subscribe(&sub);

    var sub2 = try Subscription.init(gpa, 4);
    defer sub2.deinit();
    try std.testing.expectError(error.AlreadySubscribed, ch.subscribe(&sub2));
}

test "decode delivers a FullMessage to the subscriber" {
    const gpa = std.testing.allocator;
    var eng = try Engine.init(gpa, "local", .{});
    defer eng.deinit();
    const ch = try eng.attachChannelRs("topic", sub_test_cfg);
    try ch.addMember("p1");

    var sub = try Subscription.init(gpa, 4);
    defer sub.deinit();
    try ch.subscribe(&sub);

    const payload = [_]u8{ 'h', 'e', 'l', 'l', 'o' };
    try ch.publish("m1", &payload);
    const decoded = try ch.sessionDecode("m1");
    defer gpa.free(decoded);

    try std.testing.expectEqual(@as(usize, 1), sub.count());
    const m = sub.pop().?;
    defer Subscription.freeMessage(gpa, m);
    try std.testing.expectEqualStrings("topic", m.channel_id);
    try std.testing.expectEqualStrings("m1", m.message_id);
    try std.testing.expectEqualSlices(u8, &payload, m.data);
    try std.testing.expect(sub.pop() == null);
}

test "subscriber drops decoded messages when full" {
    const gpa = std.testing.allocator;
    var eng = try Engine.init(gpa, "local", .{});
    defer eng.deinit();
    const ch = try eng.attachChannelRs("topic", sub_test_cfg);
    try ch.addMember("p1");

    var sub = try Subscription.init(gpa, 1);
    defer sub.deinit();
    try ch.subscribe(&sub);

    const payload = [_]u8{ 'w', 'o', 'r', 'l', 'd' };
    try ch.publish("m1", &payload);
    const d1 = try ch.sessionDecode("m1");
    defer gpa.free(d1);
    try ch.publish("m2", &payload);
    const d2 = try ch.sessionDecode("m2");
    defer gpa.free(d2);

    try std.testing.expectEqual(@as(usize, 1), sub.count());
    try std.testing.expectEqual(@as(usize, 1), sub.dropped());
}

const session_rs_mod = @import("session_rs.zig");

test "origin session disposes once its peer completes; disposeSession emits" {
    const gpa = std.testing.allocator;
    var rec: @import("observer.zig").Recording = .{};
    var eng = try Engine.init(gpa, "local", .{ .observer = rec.observer() });
    defer eng.deinit();
    const ch = try eng.attachChannelRs("topic", sub_test_cfg);
    try ch.addMember("p1");

    const payload = [_]u8{ 'h', 'i', '!', '!', '!' };
    try ch.publish("m1", &payload);

    const sess = ch.sessions.get("m1").?;
    try std.testing.expectEqual(session_rs_mod.SessionStage.origin, sess.stage);
    // Decoded (origin) but the peer has not completed → not disposable yet.
    try std.testing.expect(!sess.maybeDispose());
    sess.markPeerCompleted("p1");
    try std.testing.expect(sess.maybeDispose());

    ch.disposeSession("m1", "reconstructed");
    try std.testing.expect(ch.sessions.get("m1") == null);
    try std.testing.expectEqual(@as(usize, 1), rec.session_disposed);
}

test "relay session: consuming stage, reconstruct signal, drop-based disposal" {
    const gpa = std.testing.allocator;
    var eng = try Engine.init(gpa, "local", .{});
    defer eng.deinit();
    const ch = try eng.attachChannelRs("topic", sub_test_cfg);
    try ch.addMember("peerA");
    try ch.addMember("peerB");

    const payload = [_]u8{ 9, 8, 7 };
    var origin = try RsStrategy.newOrigin(gpa, sub_test_cfg, &payload);
    defer origin.deinit();
    try ch.attachRelaySession("m1", &origin.preamble);

    const sess = ch.sessions.get("m1").?;
    try std.testing.expectEqual(session_rs_mod.SessionStage.consuming, sess.stage);

    // Not decoded: disposes only when every peer is dropped.
    try std.testing.expect(!sess.maybeDispose());
    sess.dropPeer("peerA");
    try std.testing.expect(!sess.maybeDispose());
    sess.dropPeer("peerB");
    try std.testing.expect(sess.maybeDispose());

    // Reconstruction moves it to the decoded branch.
    sess.signalReconstructed();
    try std.testing.expectEqual(session_rs_mod.SessionStage.reconstructed, sess.stage);
    try std.testing.expect(sess.maybeDispose());

    ch.disposeSession("m1", "ttl_expired");
    try std.testing.expect(ch.sessions.get("m1") == null);
}

test "parked chunks replay into the session on attach" {
    const gpa = std.testing.allocator;
    var rec: @import("observer.zig").Recording = .{};
    var eng = try Engine.init(gpa, "local", .{ .observer = rec.observer() });
    defer eng.deinit();
    const ch = try eng.attachChannelRs("topic", sub_test_cfg);
    try ch.addMember("peerA");

    const payload = [_]u8{ 9, 8, 7 };
    var origin = try RsStrategy.newOrigin(gpa, sub_test_cfg, &payload);
    defer origin.deinit();

    const pr = try ch.parkChunk("m1", "peerA", 0, origin.chunks[0], 100);
    try std.testing.expectEqual(ParkResult.parked, pr);
    try std.testing.expectEqual(@as(usize, 1), ch.parkedCount("m1"));

    try ch.attachRelaySession("m1", &origin.preamble);
    try std.testing.expectEqual(@as(usize, 0), ch.parkedCount("m1"));
    try std.testing.expectEqual(@as(usize, 1), rec.chunk_rcvd); // replayed
}

test "parkChunk drops beyond max_parked_chunks" {
    const gpa = std.testing.allocator;
    var eng = try Engine.init(gpa, "local", .{});
    defer eng.deinit();
    const ch = try eng.attachChannelRs("topic", sub_test_cfg);

    const data = [_]u8{ 1, 2, 3 };
    var i: usize = 0;
    while (i < max_parked_chunks) : (i += 1) {
        try std.testing.expectEqual(ParkResult.parked, try ch.parkChunk("m1", "p", @intCast(i), &data, 0));
    }
    try std.testing.expectEqual(max_parked_chunks, ch.parkedCount("m1"));
    try std.testing.expectEqual(ParkResult.dropped_full, try ch.parkChunk("m1", "p", 999, &data, 0));
    try std.testing.expectEqual(max_parked_chunks, ch.parkedCount("m1"));
}

test "cleanup drops stale parked chunks and expired sessions" {
    const gpa = std.testing.allocator;
    var rec: @import("observer.zig").Recording = .{};
    var eng = try Engine.init(gpa, "local", .{ .observer = rec.observer() });
    defer eng.deinit();
    const ch = try eng.attachChannelRs("topic", sub_test_cfg);

    const data = [_]u8{ 1, 2, 3 };
    _ = try ch.parkChunk("m1", "p", 0, &data, 1000);

    try ch.addMember("p1");
    const payload = [_]u8{ 'a', 'b', 'c', 'd', 'e' };
    try ch.publish("m2", &payload);
    ch.sessions.get("m2").?.created_at_ms = 1000;

    // Fresh cleanup leaves both in place.
    ch.cleanup(1500);
    try std.testing.expectEqual(@as(usize, 1), ch.parkedCount("m1"));
    try std.testing.expect(ch.sessions.get("m2") != null);

    // Past both TTLs: parked chunk dropped, session disposed.
    ch.cleanup(1000 + active_session_ttl_ms + 1);
    try std.testing.expectEqual(@as(usize, 0), ch.parkedCount("m1"));
    try std.testing.expect(ch.sessions.get("m2") == null);
    try std.testing.expectEqual(@as(usize, 1), rec.session_disposed);
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
