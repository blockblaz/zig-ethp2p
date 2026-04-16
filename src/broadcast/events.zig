//! Event shapes aligned with ethp2p [`broadcast/events.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/events.go).
//! The Go reference multiplexes these on goroutine-local channels; Zig keeps the same data model with
//! explicit [`ChannelEventQueue`] / [`PeerChunkOutbox`] FIFOs for optional single-threaded event loops.
//!
//! Excluded from like-for-like porting (see `UPSTREAM.md`): Go `context.Context` on [`PeerSendChunk`]
//! (cancellation is represented by an optional opaque `session_done` waiter).

const std = @import("std");
const broadcast_types = @import("../layer/broadcast_types.zig");
const wire_broadcast = @import("../wire/broadcast.zig");

const Allocator = std.mem.Allocator;

pub const ChunkHandle = broadcast_types.ChunkHandle;
pub const Verdict = broadcast_types.Verdict;

// ---------------------------------------------------------------------------
// Engine events
// ---------------------------------------------------------------------------

/// Discriminant values match Go `engineEventKind` (`iota + 1`).
pub const EngineEventKind = enum(u8) {
    channel_created = 1,
    channel_removed = 2,
    peer_connected = 3,
    peer_handshake = 4,
    peer_gone = 5,
    peer_subscribed = 6,
    peer_unsubscribed = 7,
};

pub const EngineEvent = union(EngineEventKind) {
    /// Posted when a channel is created; `inbox` receives [`ChannelEvent`] values for that channel.
    channel_created: struct {
        channel_id: []u8,
        inbox: *ChannelEventQueue,
    },
    channel_removed: struct { channel_id: []u8 },
    peer_connected: struct {
        channel_id: []u8,
        peer_id: []u8,
        /// Opaque transport connection; integration casts to the QUIC `Conn` type in use.
        conn: ?*anyopaque = null,
    },
    peer_handshake: struct {
        channel_id: []u8,
        peer_id: []u8,
        /// Opaque `PeerConn` pointer when available.
        peer: ?*anyopaque = null,
        channels: [][]u8,
        err: ?anyerror = null,
    },
    peer_gone: struct { channel_id: []u8, peer_id: []u8 },
    peer_subscribed: struct { channel_id: []u8, peer_id: []u8 },
    peer_unsubscribed: struct { channel_id: []u8, peer_id: []u8 },

    pub fn deinit(self: *EngineEvent, allocator: Allocator) void {
        switch (self.*) {
            .channel_created => |*p| {
                allocator.free(p.channel_id);
            },
            .channel_removed => |*p| {
                allocator.free(p.channel_id);
            },
            .peer_connected => |*p| {
                allocator.free(p.channel_id);
                allocator.free(p.peer_id);
            },
            .peer_handshake => |*p| {
                allocator.free(p.channel_id);
                allocator.free(p.peer_id);
                for (p.channels) |c| allocator.free(c);
                allocator.free(p.channels);
            },
            .peer_gone => |*p| {
                allocator.free(p.channel_id);
                allocator.free(p.peer_id);
            },
            .peer_subscribed => |*p| {
                allocator.free(p.channel_id);
                allocator.free(p.peer_id);
            },
            .peer_unsubscribed => |*p| {
                allocator.free(p.channel_id);
                allocator.free(p.peer_id);
            },
        }
    }
};

// ---------------------------------------------------------------------------
// Channel events
// ---------------------------------------------------------------------------

/// Inbound chunk stream notification: header decoded; unread payload follows on `stream`.
pub const ChannelChunkStream = struct {
    peer_id: []u8,
    header: wire_broadcast.ChunkHeaderOwned,
    /// Opaque receive stream (e.g. QUIC uni stream handle at integration boundaries).
    stream: *anyopaque,
};

/// Chunk body after a reader finished loading the stream payload.
pub const ChannelChunkData = struct {
    message_id: []u8,
    peer_id: []u8,
    chunk_id: []u8,
    payload: []u8,
};

/// Remote peer opened a session control stream (`Sess.session_open`).
pub const ChannelSessionOpen = struct {
    peer_id: []u8,
    msg: wire_broadcast.SessOwned,
};

pub const ChannelPeerChange = struct {
    peer_id: []u8,
    /// Non-null means joined; null means left.
    peer_ref: ?*anyopaque,
};

pub const ChannelPeerReconstructed = struct {
    message_id: []u8,
    peer_id: []u8,
};

/// Publish request (strategy is type-erased in Go; Zig uses an opaque pointer).
pub const ChannelPublish = struct {
    message_id: []u8,
    strategy: ?*anyopaque,
    preamble: []u8,
};

pub const ChannelChunkSent = struct {
    message_id: []u8,
    peer_id: []u8,
    handle: ChunkHandle,
    err: ?anyerror,
    /// Matches Go `int` on the reference platform (use `isize`).
    size: isize,
};

pub const ChannelRoutingUpdate = struct {
    peer_id: []u8,
    message_id: []u8,
    msg: wire_broadcast.SessOwned,
};

pub const ChannelWork = struct {
    message_id: []u8,
};

pub const ChannelVerifyResult = struct {
    message_id: []u8,
    peer_id: []u8,
    chunk_id: []u8,
    payload: []u8,
    verdict: Verdict,
};

pub const ChannelDecoded = struct {
    message_id: []u8,
    payload: []u8,
    err: ?anyerror,
};

pub const ChannelEvent = union(enum) {
    chunk_stream: ChannelChunkStream,
    chunk_data: ChannelChunkData,
    session_open: ChannelSessionOpen,
    session_disposed: struct { message_id: []u8 },
    peer_change: ChannelPeerChange,
    peer_reconstructed: ChannelPeerReconstructed,
    publish: ChannelPublish,
    chunk_sent: ChannelChunkSent,
    routing_update: ChannelRoutingUpdate,
    work: ChannelWork,
    verify_result: ChannelVerifyResult,
    decoded: ChannelDecoded,

    pub fn deinit(self: *ChannelEvent, allocator: Allocator) void {
        switch (self.*) {
            .chunk_stream => |*p| {
                allocator.free(p.peer_id);
                p.header.deinit(allocator);
            },
            .chunk_data => |*p| {
                allocator.free(p.message_id);
                allocator.free(p.peer_id);
                allocator.free(p.chunk_id);
                allocator.free(p.payload);
            },
            .session_open => |*p| {
                allocator.free(p.peer_id);
                p.msg.deinit(allocator);
            },
            .session_disposed => |*p| {
                allocator.free(p.message_id);
            },
            .peer_change => |*p| {
                allocator.free(p.peer_id);
            },
            .peer_reconstructed => |*p| {
                allocator.free(p.message_id);
                allocator.free(p.peer_id);
            },
            .publish => |*p| {
                allocator.free(p.message_id);
                allocator.free(p.preamble);
            },
            .chunk_sent => |*p| {
                allocator.free(p.message_id);
                allocator.free(p.peer_id);
            },
            .routing_update => |*p| {
                allocator.free(p.peer_id);
                allocator.free(p.message_id);
                p.msg.deinit(allocator);
            },
            .work => |*p| {
                allocator.free(p.message_id);
            },
            .verify_result => |*p| {
                allocator.free(p.message_id);
                allocator.free(p.peer_id);
                allocator.free(p.chunk_id);
                allocator.free(p.payload);
            },
            .decoded => |*p| {
                allocator.free(p.message_id);
                allocator.free(p.payload);
            },
        }
    }
};

pub const ChannelEventQueue = struct {
    allocator: Allocator,
    items: std.ArrayListUnmanaged(ChannelEvent),

    pub fn init(allocator: Allocator) ChannelEventQueue {
        return .{ .allocator = allocator, .items = .{} };
    }

    pub fn deinit(self: *ChannelEventQueue) void {
        for (self.items.items) |*ev| {
            ev.deinit(self.allocator);
        }
        self.items.deinit(self.allocator);
    }

    pub fn post(self: *ChannelEventQueue, ev: ChannelEvent) Allocator.Error!void {
        try self.items.append(self.allocator, ev);
    }

    /// FIFO pop; `O(n)` shift — fine for tests and shallow queues (same pattern as a naive Go chan drain).
    pub fn popFront(self: *ChannelEventQueue) ?ChannelEvent {
        if (self.items.items.len == 0) return null;
        return self.items.orderedRemove(0);
    }

    pub fn len(self: *const ChannelEventQueue) usize {
        return self.items.items.len;
    }
};

// ---------------------------------------------------------------------------
// Peer control events (session → PeerConn outbound loop)
// ---------------------------------------------------------------------------

pub const PeerOpenSession = struct {
    channel_id: []u8,
    message_id: []u8,
    preamble: []u8,
    initial_routing: []u8,
    channel_inbox: *ChannelEventQueue,
    chunk_outbox: *PeerChunkOutbox,
};

pub const PeerSendRouting = struct {
    channel_id: []u8,
    message_id: []u8,
    update: []u8,
};

pub const PeerCloseSession = struct {
    channel_id: []u8,
    message_id: []u8,
};

pub const PeerCloseStream = struct {
    channel_id: []u8,
    message_id: []u8,
};

pub const PeerCtrlEvent = union(enum) {
    open_session: PeerOpenSession,
    subscribe: struct { channel_id: []u8 },
    unsubscribe: struct { channel_id: []u8 },
    send_routing: PeerSendRouting,
    close_session: PeerCloseSession,
    close_stream: PeerCloseStream,

    pub fn deinit(self: *PeerCtrlEvent, allocator: Allocator) void {
        switch (self.*) {
            .open_session => |*p| {
                allocator.free(p.channel_id);
                allocator.free(p.message_id);
                allocator.free(p.preamble);
                allocator.free(p.initial_routing);
            },
            .subscribe => |*p| {
                allocator.free(p.channel_id);
            },
            .unsubscribe => |*p| {
                allocator.free(p.channel_id);
            },
            .send_routing => |*p| {
                allocator.free(p.channel_id);
                allocator.free(p.message_id);
                allocator.free(p.update);
            },
            .close_session => |*p| {
                allocator.free(p.channel_id);
                allocator.free(p.message_id);
            },
            .close_stream => |*p| {
                allocator.free(p.channel_id);
                allocator.free(p.message_id);
            },
        }
    }
};

pub const PeerSendChunk = struct {
    peer_id: []u8,
    channel_id: []u8,
    message_id: []u8,
    handle: ChunkHandle,
    chunk_id: []u8,
    payload: []u8,
    /// Where the outbound loop posts [`ChannelEvent.chunk_sent`].
    result_inbox: *ChannelEventQueue,
    /// Optional opaque waiter (e.g. atomic flag or condition) signalled when the session ends.
    session_done: ?*anyopaque = null,

    pub fn deinit(self: *PeerSendChunk, allocator: Allocator) void {
        allocator.free(self.peer_id);
        allocator.free(self.channel_id);
        allocator.free(self.message_id);
        allocator.free(self.chunk_id);
        allocator.free(self.payload);
    }
};

pub const PeerChunkOutbox = struct {
    allocator: Allocator,
    items: std.ArrayListUnmanaged(PeerSendChunk),

    pub fn init(allocator: Allocator) PeerChunkOutbox {
        return .{ .allocator = allocator, .items = .{} };
    }

    pub fn deinit(self: *PeerChunkOutbox) void {
        for (self.items.items) |*c| {
            c.deinit(self.allocator);
        }
        self.items.deinit(self.allocator);
    }

    pub fn post(self: *PeerChunkOutbox, chunk: PeerSendChunk) Allocator.Error!void {
        try self.items.append(self.allocator, chunk);
    }

    pub fn popFront(self: *PeerChunkOutbox) ?PeerSendChunk {
        if (self.items.items.len == 0) return null;
        return self.items.orderedRemove(0);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "EngineEventKind ordinals match Go iota+1" {
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(EngineEventKind.channel_created));
    try std.testing.expectEqual(@as(u8, 7), @intFromEnum(EngineEventKind.peer_unsubscribed));
}

test "ChannelEventQueue fifo and deinit" {
    const alloc = std.testing.allocator;
    var q = ChannelEventQueue.init(alloc);
    defer q.deinit();

    try q.post(.{ .work = .{ .message_id = try alloc.dupe(u8, "m1") } });
    try q.post(.{ .decoded = .{
        .message_id = try alloc.dupe(u8, "m2"),
        .payload = try alloc.dupe(u8, "payload"),
        .err = null,
    } });

    try std.testing.expectEqual(@as(usize, 2), q.len());
    var a = q.popFront().?;
    defer a.deinit(alloc);
    try std.testing.expectEqualStrings("m1", a.work.message_id);

    var b = q.popFront().?;
    defer b.deinit(alloc);
    try std.testing.expectEqualStrings("m2", b.decoded.message_id);
    try std.testing.expectEqualStrings("payload", b.decoded.payload);
}

test "PeerCtrlEvent and PeerChunkOutbox roundtrip" {
    const alloc = std.testing.allocator;
    var inbox = ChannelEventQueue.init(alloc);
    defer inbox.deinit();
    var out = PeerChunkOutbox.init(alloc);
    defer out.deinit();

    var ev: PeerCtrlEvent = .{ .open_session = .{
        .channel_id = try alloc.dupe(u8, "ch"),
        .message_id = try alloc.dupe(u8, "mid"),
        .preamble = try alloc.dupe(u8, &.{ 1, 2 }),
        .initial_routing = try alloc.dupe(u8, &.{3}),
        .channel_inbox = &inbox,
        .chunk_outbox = &out,
    } };
    defer ev.deinit(alloc);

    try out.post(.{
        .peer_id = try alloc.dupe(u8, "peer"),
        .channel_id = try alloc.dupe(u8, "ch"),
        .message_id = try alloc.dupe(u8, "mid"),
        .handle = 7,
        .chunk_id = try alloc.dupe(u8, "cid"),
        .payload = try alloc.dupe(u8, "pl"),
        .result_inbox = &inbox,
        .session_done = null,
    });

    var chunk = out.popFront().?;
    defer chunk.deinit(alloc);
    try std.testing.expectEqual(@as(ChunkHandle, 7), chunk.handle);
}
