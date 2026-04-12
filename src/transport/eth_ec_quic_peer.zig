//! Poll-driven `PeerConn` state machine for the ethp2p QUIC peer lifecycle.
//!
//! Models the lifecycle from `broadcast/peer.go`, `peer_ctrl.go`, `peer_in.go`
//! in the Go reference without goroutines.  Callers drive progress by calling
//! `poll` on the underlying `QuicEndpoint` then calling `drive()` on this struct.
//!
//! SESS/CHUNK inbound streams can be forwarded into `broadcast.Engine` via
//! `broadcast/engine_quic.zig` (`EngineQuicHost`).  Callbacks receive an optional
//! `user_data` pointer for embedder context.

const std = @import("std");
const quic = @import("quic");
const broadcast = @import("../wire/broadcast.zig");
const bcast_stream = @import("../wire/bcast_stream.zig");
const protocol = @import("../wire/protocol.zig");

/// Lifecycle state of a `PeerConn`.
pub const PeerConnState = enum {
    /// Handshake not yet started.
    idle,
    /// Outbound BCAST UNI stream opened; waiting for the peer's inbound BCAST UNI stream.
    handshaking,
    /// Both BCAST streams are in place; active session.
    active,
    /// Terminal state — peer closed or error.
    closed,
};

/// Inbound stream kind, matched by the single-byte selector (protocol.zig).
pub const InboundStreamKind = enum { bcast, sess, chunk, unknown };

/// A minimal peer connection that manages the BCAST control streams and
/// dispatches incoming UNI streams by protocol type.
///
/// Matches `PeerConn` in `broadcast/peer.go`.
pub const PeerConn = struct {
    conn: *quic.QuicConnection,
    ep: *quic.QuicEndpoint,
    state: PeerConnState,

    /// Our outbound BCAST UNI stream (`ctrlOut` in peer.go).
    bcast_out: ?*quic.QuicStream,
    /// The peer's inbound BCAST UNI stream (`ctrlIn` in peer.go).
    bcast_in: ?*quic.QuicStream,

    allocator: std.mem.Allocator,

    /// Opaque context passed to stream callbacks (e.g. `*EngineQuicHost`).
    user_data: ?*anyopaque = null,

    /// Optional callback for inbound SESS streams.
    on_sess_stream: ?*const fn (user_data: ?*anyopaque, pc: *PeerConn, st: *quic.QuicStream) void = null,
    /// Optional callback for inbound CHUNK streams.
    on_chunk_stream: ?*const fn (user_data: ?*anyopaque, pc: *PeerConn, st: *quic.QuicStream) void = null,

    pub fn init(
        allocator: std.mem.Allocator,
        conn: *quic.QuicConnection,
        ep: *quic.QuicEndpoint,
    ) PeerConn {
        return .{
            .conn = conn,
            .ep = ep,
            .state = .idle,
            .bcast_out = null,
            .bcast_in = null,
            .allocator = allocator,
        };
    }

    /// Start the handshake: open the outbound BCAST UNI stream and write
    /// the handshake message.
    ///
    /// Matches `peer.go handshake()` writer goroutine:
    ///   s, err := conn.OpenUniStream(ctx)
    ///   protocol.WriteSelector(s, PROTOCOL_BCAST)
    ///   WriteFrame(s, hsMsg)
    ///
    /// The caller must continue calling `drive()` to accept the peer's
    /// inbound BCAST stream.
    pub fn beginHandshake(
        self: *PeerConn,
        poll_peer: ?*quic.QuicEndpoint,
        hs: broadcast.Handshake,
    ) !void {
        if (self.state != .idle) return error.InvalidState;

        const out = try quic.streamMakeUni(self.conn, poll_peer);
        self.bcast_out = out;

        var buf = std.ArrayList(u8).empty;
        defer buf.deinit(self.allocator);
        try bcast_stream.writeBcastHandshakeOpen(buf.writer(self.allocator), self.allocator, hs);
        try quic.streamQueueWrite(out, buf.items);

        self.state = .handshaking;
    }

    /// Drive the peer connection forward (call after `quic.poll`).
    ///
    /// - In `handshaking` state: flush the outbound BCAST write and try to
    ///   accept the peer's inbound BCAST UNI stream.
    /// - In `active` state: process all pending inbound UNI streams.
    ///
    /// Returns `true` when a state transition occurred (caller may want to act).
    pub fn drive(self: *PeerConn) bool {
        switch (self.state) {
            .idle, .closed => return false,
            .handshaking => {
                // Try to accept the peer's BCAST UNI stream.
                if (self.bcast_in == null) {
                    if (quic.tryAcceptIncomingUniStream(self.conn)) |st| {
                        self.bcast_in = st;
                        self.state = .active;
                        return true;
                    }
                }
                return false;
            },
            .active => {
                var transitioned = false;
                // Process incoming UNI streams (runAcceptLoop in peer_in.go).
                while (quic.tryAcceptIncomingUniStream(self.conn)) |st| {
                    self.dispatchInboundUniStream(st);
                    transitioned = true;
                }
                return transitioned;
            },
        }
    }

    /// Dispatch an inbound UNI stream by reading its single-byte protocol selector.
    ///
    /// Matches `runAcceptLoop` in `peer_in.go`:
    ///   prot, err := protocol.ReadSelector(s)
    ///   switch prot {
    ///   case SESS: go runInboundSession(s)
    ///   case CHUNK: go processChunk(s)
    ///   }
    ///
    /// Handlers are optional callbacks set by the owning Engine.  When null,
    /// the stream is acknowledged and discarded (graceful no-op).
    fn dispatchInboundUniStream(self: *PeerConn, st: *quic.QuicStream) void {
        const raw = quic.streamReadSlice(st);
        if (raw.len == 0) return;

        const sel: protocol.Protocol = @enumFromInt(raw[0]);
        switch (sel) {
            .bcast => {
                // Secondary BCAST stream from peer (allowed but typically ignored
                // once the primary control stream is established).
                if (self.bcast_in == null) self.bcast_in = st;
            },
            .sess => {
                if (self.on_sess_stream) |cb| cb(self.user_data, self, st) else quic.streamCancelRead(st);
            },
            .chunk => {
                if (self.on_chunk_stream) |cb| cb(self.user_data, self, st) else quic.streamCancelRead(st);
            },
            else => {
                // Unknown protocol — cancel to release flow-control credit.
                quic.streamCancelRead(st);
            },
        }
    }

    /// Graceful shutdown: close the outbound BCAST stream and mark closed.
    pub fn close(self: *PeerConn) void {
        if (self.bcast_out) |s| quic.streamCancelWrite(s);
        self.bcast_out = null;
        self.bcast_in = null;
        self.state = .closed;
    }
};

/// Convenience re-export of the type accepted by `PeerConn.beginHandshake`.
pub const HandshakeArgs = broadcast.Handshake;
