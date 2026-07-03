//! Broadcast-system event observer, aligned with ethp2p
//! [`broadcast/observer.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/observer.go).
//!
//! Zig has no interfaces, so `Observer` is type-erased (a `ptr` + `vtable`
//! pair, like `std.mem.Allocator`); `noop` is the do-nothing default used by
//! `EngineConfig`. The full 15-callback surface mirrors the Go interface for
//! forward compatibility. Emission is wired at the sites that exist in the Zig
//! port today — channel attach, session start/decode, chunk receive, peer
//! subscribe/unsubscribe. The remaining callbacks (`onPeerHandshook`/`Gone`,
//! `onSessionDisposed`, `onChunkSent`/`Error`, `onRoutingUpdate`,
//! `onPreambleOpened`, `onStrategyProgress`) are emitted as their subsystems
//! land (engine peer tracking; session disposal, #62; strategy hooks).

const std = @import("std");
const broadcast_types = @import("../layer/broadcast_types.zig");

pub const Verdict = broadcast_types.Verdict;
pub const SessionRole = broadcast_types.SessionRole;

pub const Observer = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        onChannelAttached: *const fn (ctx: *anyopaque, channel_id: []const u8, err: ?anyerror) void,
        onChannelDropped: *const fn (ctx: *anyopaque, channel_id: []const u8) void,
        onPeerHandshook: *const fn (ctx: *anyopaque, peer_id: []const u8, version: u32, channels: []const []const u8) void,
        onPeerSubscribed: *const fn (ctx: *anyopaque, peer_id: []const u8, channel_id: []const u8) void,
        onPeerUnsubscribed: *const fn (ctx: *anyopaque, peer_id: []const u8, channel_id: []const u8) void,
        onPeerGone: *const fn (ctx: *anyopaque, peer_id: []const u8) void,
        onSessionStarted: *const fn (ctx: *anyopaque, channel_id: []const u8, message_id: []const u8, role: SessionRole) void,
        onSessionDecoded: *const fn (ctx: *anyopaque, channel_id: []const u8, message_id: []const u8, latency_us: i64) void,
        onSessionDisposed: *const fn (ctx: *anyopaque, channel_id: []const u8, message_id: []const u8, reason: []const u8) void,
        onChunkSent: *const fn (ctx: *anyopaque, peer_id: []const u8, channel_id: []const u8, message_id: []const u8, bytes_sent: usize) void,
        onChunkRcvd: *const fn (ctx: *anyopaque, peer_id: []const u8, channel_id: []const u8, message_id: []const u8, verdict: Verdict) void,
        onChunkError: *const fn (ctx: *anyopaque, channel_id: []const u8, message_id: []const u8, err: anyerror) void,
        onRoutingUpdate: *const fn (ctx: *anyopaque, peer_id: []const u8, channel_id: []const u8, message_id: []const u8) void,
        onPreambleOpened: *const fn (ctx: *anyopaque, peer_id: []const u8, channel_id: []const u8, message_id: []const u8) void,
        onStrategyProgress: *const fn (ctx: *anyopaque, channel_id: []const u8, message_id: []const u8, chunks_have: usize, chunks_need: usize) void,
    };

    // Channel lifecycle
    pub fn channelAttached(self: Observer, channel_id: []const u8, err: ?anyerror) void {
        self.vtable.onChannelAttached(self.ptr, channel_id, err);
    }
    pub fn channelDropped(self: Observer, channel_id: []const u8) void {
        self.vtable.onChannelDropped(self.ptr, channel_id);
    }

    // Peer lifecycle
    pub fn peerHandshook(self: Observer, peer_id: []const u8, version: u32, channels: []const []const u8) void {
        self.vtable.onPeerHandshook(self.ptr, peer_id, version, channels);
    }
    pub fn peerSubscribed(self: Observer, peer_id: []const u8, channel_id: []const u8) void {
        self.vtable.onPeerSubscribed(self.ptr, peer_id, channel_id);
    }
    pub fn peerUnsubscribed(self: Observer, peer_id: []const u8, channel_id: []const u8) void {
        self.vtable.onPeerUnsubscribed(self.ptr, peer_id, channel_id);
    }
    pub fn peerGone(self: Observer, peer_id: []const u8) void {
        self.vtable.onPeerGone(self.ptr, peer_id);
    }

    // Session lifecycle
    pub fn sessionStarted(self: Observer, channel_id: []const u8, message_id: []const u8, role: SessionRole) void {
        self.vtable.onSessionStarted(self.ptr, channel_id, message_id, role);
    }
    pub fn sessionDecoded(self: Observer, channel_id: []const u8, message_id: []const u8, latency_us: i64) void {
        self.vtable.onSessionDecoded(self.ptr, channel_id, message_id, latency_us);
    }
    pub fn sessionDisposed(self: Observer, channel_id: []const u8, message_id: []const u8, reason: []const u8) void {
        self.vtable.onSessionDisposed(self.ptr, channel_id, message_id, reason);
    }

    // Chunk events
    pub fn chunkSent(self: Observer, peer_id: []const u8, channel_id: []const u8, message_id: []const u8, bytes_sent: usize) void {
        self.vtable.onChunkSent(self.ptr, peer_id, channel_id, message_id, bytes_sent);
    }
    pub fn chunkRcvd(self: Observer, peer_id: []const u8, channel_id: []const u8, message_id: []const u8, verdict: Verdict) void {
        self.vtable.onChunkRcvd(self.ptr, peer_id, channel_id, message_id, verdict);
    }
    pub fn chunkError(self: Observer, channel_id: []const u8, message_id: []const u8, err: anyerror) void {
        self.vtable.onChunkError(self.ptr, channel_id, message_id, err);
    }

    // Routing and strategy progress
    pub fn routingUpdate(self: Observer, peer_id: []const u8, channel_id: []const u8, message_id: []const u8) void {
        self.vtable.onRoutingUpdate(self.ptr, peer_id, channel_id, message_id);
    }
    pub fn preambleOpened(self: Observer, peer_id: []const u8, channel_id: []const u8, message_id: []const u8) void {
        self.vtable.onPreambleOpened(self.ptr, peer_id, channel_id, message_id);
    }
    pub fn strategyProgress(self: Observer, channel_id: []const u8, message_id: []const u8, chunks_have: usize, chunks_need: usize) void {
        self.vtable.onStrategyProgress(self.ptr, channel_id, message_id, chunks_have, chunks_need);
    }
};

// --- NoOpObserver (ethp2p `NoOpObserver`) -----------------------------------

const noop_impl = struct {
    fn channelAttached(_: *anyopaque, _: []const u8, _: ?anyerror) void {}
    fn channelDropped(_: *anyopaque, _: []const u8) void {}
    fn peerHandshook(_: *anyopaque, _: []const u8, _: u32, _: []const []const u8) void {}
    fn peerSubscribed(_: *anyopaque, _: []const u8, _: []const u8) void {}
    fn peerUnsubscribed(_: *anyopaque, _: []const u8, _: []const u8) void {}
    fn peerGone(_: *anyopaque, _: []const u8) void {}
    fn sessionStarted(_: *anyopaque, _: []const u8, _: []const u8, _: SessionRole) void {}
    fn sessionDecoded(_: *anyopaque, _: []const u8, _: []const u8, _: i64) void {}
    fn sessionDisposed(_: *anyopaque, _: []const u8, _: []const u8, _: []const u8) void {}
    fn chunkSent(_: *anyopaque, _: []const u8, _: []const u8, _: []const u8, _: usize) void {}
    fn chunkRcvd(_: *anyopaque, _: []const u8, _: []const u8, _: []const u8, _: Verdict) void {}
    fn chunkError(_: *anyopaque, _: []const u8, _: []const u8, _: anyerror) void {}
    fn routingUpdate(_: *anyopaque, _: []const u8, _: []const u8, _: []const u8) void {}
    fn preambleOpened(_: *anyopaque, _: []const u8, _: []const u8, _: []const u8) void {}
    fn strategyProgress(_: *anyopaque, _: []const u8, _: []const u8, _: usize, _: usize) void {}
};

const noop_vtable: Observer.VTable = .{
    .onChannelAttached = noop_impl.channelAttached,
    .onChannelDropped = noop_impl.channelDropped,
    .onPeerHandshook = noop_impl.peerHandshook,
    .onPeerSubscribed = noop_impl.peerSubscribed,
    .onPeerUnsubscribed = noop_impl.peerUnsubscribed,
    .onPeerGone = noop_impl.peerGone,
    .onSessionStarted = noop_impl.sessionStarted,
    .onSessionDecoded = noop_impl.sessionDecoded,
    .onSessionDisposed = noop_impl.sessionDisposed,
    .onChunkSent = noop_impl.chunkSent,
    .onChunkRcvd = noop_impl.chunkRcvd,
    .onChunkError = noop_impl.chunkError,
    .onRoutingUpdate = noop_impl.routingUpdate,
    .onPreambleOpened = noop_impl.preambleOpened,
    .onStrategyProgress = noop_impl.strategyProgress,
};

/// The default do-nothing observer.
pub const noop: Observer = .{ .ptr = undefined, .vtable = &noop_vtable };

// --- Tests ------------------------------------------------------------------

const testing = std.testing;

/// A test observer that counts each callback and records the last session role.
pub const Recording = struct {
    session_started: usize = 0,
    session_decoded: usize = 0,
    chunk_rcvd: usize = 0,
    peer_subscribed: usize = 0,
    peer_unsubscribed: usize = 0,
    channel_attached: usize = 0,
    last_role: ?SessionRole = null,
    last_verdict: ?Verdict = null,

    pub fn observer(self: *Recording) Observer {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Observer.VTable = .{
        .onChannelAttached = onChannelAttached,
        .onChannelDropped = noop_impl.channelDropped,
        .onPeerHandshook = noop_impl.peerHandshook,
        .onPeerSubscribed = onPeerSubscribed,
        .onPeerUnsubscribed = onPeerUnsubscribed,
        .onPeerGone = noop_impl.peerGone,
        .onSessionStarted = onSessionStarted,
        .onSessionDecoded = onSessionDecoded,
        .onSessionDisposed = noop_impl.sessionDisposed,
        .onChunkSent = noop_impl.chunkSent,
        .onChunkRcvd = onChunkRcvd,
        .onChunkError = noop_impl.chunkError,
        .onRoutingUpdate = noop_impl.routingUpdate,
        .onPreambleOpened = noop_impl.preambleOpened,
        .onStrategyProgress = noop_impl.strategyProgress,
    };

    fn onChannelAttached(ctx: *anyopaque, _: []const u8, _: ?anyerror) void {
        cast(ctx).channel_attached += 1;
    }
    fn onPeerSubscribed(ctx: *anyopaque, _: []const u8, _: []const u8) void {
        cast(ctx).peer_subscribed += 1;
    }
    fn onPeerUnsubscribed(ctx: *anyopaque, _: []const u8, _: []const u8) void {
        cast(ctx).peer_unsubscribed += 1;
    }
    fn onSessionStarted(ctx: *anyopaque, _: []const u8, _: []const u8, role: SessionRole) void {
        const self = cast(ctx);
        self.session_started += 1;
        self.last_role = role;
    }
    fn onSessionDecoded(ctx: *anyopaque, _: []const u8, _: []const u8, _: i64) void {
        cast(ctx).session_decoded += 1;
    }
    fn onChunkRcvd(ctx: *anyopaque, _: []const u8, _: []const u8, _: []const u8, verdict: Verdict) void {
        const self = cast(ctx);
        self.chunk_rcvd += 1;
        self.last_verdict = verdict;
    }

    fn cast(ctx: *anyopaque) *Recording {
        return @ptrCast(@alignCast(ctx));
    }
};

test "noop observer dispatches without effect" {
    const o = noop;
    o.channelAttached("ch", null);
    o.sessionStarted("ch", "m", .origin);
    o.chunkRcvd("p", "ch", "m", .accepted);
}

test "recording observer captures dispatched events" {
    var rec: Recording = .{};
    const o = rec.observer();
    o.channelAttached("ch", null);
    o.sessionStarted("ch", "m", .relay);
    o.sessionDecoded("ch", "m", 1234);
    o.chunkRcvd("p", "ch", "m", .redundant);
    o.peerSubscribed("p", "ch");

    try testing.expectEqual(@as(usize, 1), rec.channel_attached);
    try testing.expectEqual(@as(usize, 1), rec.session_started);
    try testing.expectEqual(SessionRole.relay, rec.last_role.?);
    try testing.expectEqual(@as(usize, 1), rec.session_decoded);
    try testing.expectEqual(@as(usize, 1), rec.chunk_rcvd);
    try testing.expectEqual(Verdict.redundant, rec.last_verdict.?);
    try testing.expectEqual(@as(usize, 1), rec.peer_subscribed);
}
