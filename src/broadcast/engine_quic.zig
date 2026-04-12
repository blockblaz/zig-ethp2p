//! Wire `transport/eth_ec_quic_peer.zig` `PeerConn` inbound SESS/CHUNK streams into
//! `broadcast/engine.zig` `Engine` / `ChannelRs` (issue #37).
//!
//! After TLS + BCAST handshake, call `wireEngine`, then `finishBcastHandshakeRead`
//! to capture the peer id. Drive `quic.poll` on both endpoints, then `PeerConn.drive`
//! (via `engineQuicDrive`) so inbound SESS opens relay sessions and CHUNK frames
//! call `relayIngestChunkVerifiedEngine`.

const std = @import("std");
const quic = @import("quic");
const peer_mod = @import("../transport/eth_ec_quic_peer.zig");
const Engine = @import("engine.zig").Engine;
const rs_strategy = @import("../layer/rs_strategy.zig");
const chunk_stream = @import("../wire/chunk_stream.zig");
const sess_stream = @import("../wire/sess_stream.zig");
const bcast_stream = @import("../wire/bcast_stream.zig");
const protocol = @import("../wire/protocol.zig");
const wire_rs = @import("../wire/rs.zig");

const PeerConn = peer_mod.PeerConn;

/// Bridges one QUIC `PeerConn` to an `Engine` for inbound RS relay traffic.
pub const EngineQuicHost = struct {
    engine: *Engine,
    allocator: std.mem.Allocator,
    peer: PeerConn,
    /// Set by `finishBcastHandshakeRead` from the peer's BCAST `peer_handshake`.
    remote_peer_id: []u8 = &.{},
    /// Peer endpoint to co-poll while draining UNI streams (loopback tests).
    peer_ep: ?*quic.QuicEndpoint = null,

    pub fn init(allocator: std.mem.Allocator, engine: *Engine, conn: *quic.QuicConnection, ep: *quic.QuicEndpoint) EngineQuicHost {
        return .{
            .engine = engine,
            .allocator = allocator,
            .peer = PeerConn.init(allocator, conn, ep),
        };
    }

    pub fn deinit(self: *EngineQuicHost) void {
        self.peer.close();
        if (self.remote_peer_id.len != 0) {
            self.allocator.free(self.remote_peer_id);
        }
    }

    /// Install SESS/CHUNK handlers that forward into `Engine` channels.
    pub fn wireEngine(self: *EngineQuicHost) void {
        self.peer.user_data = @ptrCast(self);
        self.peer.on_sess_stream = engineQuicOnSessStream;
        self.peer.on_chunk_stream = engineQuicOnChunkStream;
    }

    pub fn setPeerEndpoint(self: *EngineQuicHost, peer_ep: ?*quic.QuicEndpoint) void {
        self.peer_ep = peer_ep;
    }

    /// After `PeerConn` reaches `.active`, read our inbound BCAST stream and
    /// store the peer's `peer_id` (for chunk/session relay attribution).
    pub fn finishBcastHandshakeRead(self: *EngineQuicHost) !void {
        const st = self.peer.bcast_in orelse return error.MissingBcastIn;
        const buf = try drainUniStream(self.allocator, st, self.peer.ep, self.peer_ep);
        defer self.allocator.free(buf);
        var fbs = std.io.fixedBufferStream(buf);
        var owned = try bcast_stream.readBcastPeerHandshake(self.allocator, fbs.reader());
        defer owned.deinit(self.allocator);
        switch (owned) {
            .peer_handshake => |h| {
                if (self.remote_peer_id.len != 0) self.allocator.free(self.remote_peer_id);
                self.remote_peer_id = try self.allocator.dupe(u8, h.peer_id);
            },
            else => return error.ExpectedPeerHandshake,
        }
    }

    pub fn drive(self: *EngineQuicHost) bool {
        return self.peer.drive();
    }
};

fn engineQuicOnSessStream(user_data: ?*anyopaque, pc: *PeerConn, st: *quic.QuicStream) void {
    _ = pc;
    const host: *EngineQuicHost = @ptrCast(@alignCast(user_data orelse return));
    handleSessStream(host, st) catch {};
}

fn engineQuicOnChunkStream(user_data: ?*anyopaque, pc: *PeerConn, st: *quic.QuicStream) void {
    _ = pc;
    const host: *EngineQuicHost = @ptrCast(@alignCast(user_data orelse return));
    handleChunkStream(host, st) catch {};
}

fn preambleOwnedToRs(allocator: std.mem.Allocator, owned: wire_rs.PreambleOwned) (std.mem.Allocator.Error || error{InvalidPreambleHash})!rs_strategy.RsPreamble {
    if (owned.hash.len != 32) {
        var o = owned;
        o.deinit(allocator);
        return error.InvalidPreambleHash;
    }
    var msg_hash: [32]u8 = undefined;
    @memcpy(&msg_hash, owned.hash);

    const n = owned.hashes.len;
    const nd = owned.num_data;
    const np = owned.num_parity;
    const ml = owned.length;

    const hashes = try allocator.alloc([]u8, n);
    errdefer {
        for (hashes) |row| allocator.free(row);
        allocator.free(hashes);
    }
    for (owned.hashes, 0..) |h, i| {
        hashes[i] = try allocator.dupe(u8, h);
    }
    var o = owned;
    o.deinit(allocator);

    return .{
        .data_chunks = nd,
        .parity_chunks = np,
        .message_length = ml,
        .chunk_hashes = hashes,
        .message_hash = msg_hash,
    };
}

fn handleSessStream(host: *EngineQuicHost, st: *quic.QuicStream) !void {
    const buf = try drainUniStream(host.allocator, st, host.peer.ep, host.peer_ep);
    defer host.allocator.free(buf);
    var fbs = std.io.fixedBufferStream(buf);
    const r = fbs.reader();
    const sel = try protocol.readSelectorByte(r);
    if (sel != .sess) return;
    var open_msg = try sess_stream.readSessSessionOpenAfterSelector(host.allocator, r);
    defer open_msg.deinit(host.allocator);
    const open = switch (open_msg) {
        .session_open => |o| o,
        else => return,
    };

    const preamble_owned = try wire_rs.decodePreamble(host.allocator, open.preamble);
    var rs_pre = try preambleOwnedToRs(host.allocator, preamble_owned);
    errdefer rs_pre.deinit(host.allocator);

    const ch = host.engine.channelRs(open.channel) orelse return error.UnknownChannel;
    try ch.attachRelaySession(open.message_id, &rs_pre);
    rs_pre.deinit(host.allocator);
}

fn handleChunkStream(host: *EngineQuicHost, st: *quic.QuicStream) !void {
    if (host.remote_peer_id.len == 0) return error.MissingRemotePeerId;

    const buf = try drainUniStream(host.allocator, st, host.peer.ep, host.peer_ep);
    defer host.allocator.free(buf);
    var fbs = std.io.fixedBufferStream(buf);
    var chunk_in = try chunk_stream.readChunkStream(host.allocator, fbs.reader());
    defer chunk_in.deinit(host.allocator);

    const ch = host.engine.channelRs(chunk_in.header.channel) orelse return error.UnknownChannel;

    const ident = try wire_rs.decodeChunkIdent(host.allocator, chunk_in.header.chunk_id);

    _ = try ch.relayIngestChunkVerifiedEngine(
        chunk_in.header.message_id,
        host.remote_peer_id,
        .{ .index = ident.index },
        chunk_in.payload,
        null,
    );
}

/// Poll until a UNI stream's buffered length stabilizes, then copy out.
fn drainUniStream(
    allocator: std.mem.Allocator,
    st: *quic.QuicStream,
    ep: *quic.QuicEndpoint,
    peer: ?*quic.QuicEndpoint,
) ![]u8 {
    var i: u32 = 0;
    while (i < 30_000) : (i += 1) {
        try quic.poll(ep, 0);
        if (peer) |p| try quic.poll(p, 0);
        const raw = quic.streamReadSlice(st);
        if (raw.len == 0) continue;

        var last = raw.len;
        var stable: u32 = 0;
        var j: u32 = 0;
        while (j < 2_000) : (j += 1) {
            try quic.poll(ep, 0);
            if (peer) |p| try quic.poll(p, 0);
            const r2 = quic.streamReadSlice(st);
            if (r2.len == last) {
                stable += 1;
                if (stable >= 2) return try allocator.dupe(u8, r2);
            } else {
                last = r2.len;
                stable = 0;
            }
        }
        return try allocator.dupe(u8, quic.streamReadSlice(st));
    }
    return error.StreamDrainTimeout;
}
