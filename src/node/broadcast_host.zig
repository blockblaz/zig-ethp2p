//! Turnkey RS-broadcast node: the assembly that `transport/eth_ec_quic_enabled.zig`
//! only exercises as test sequences, packaged as a reusable, poll-driven Host.
//!
//! `BroadcastNode` owns a QUIC listen endpoint (server) and a dial endpoint
//! (client), a `broadcast.Engine`, a per-peer `EngineQuicHost`, and a per-channel
//! `Subscription`. It fills the gaps a raw `EngineQuicHost` leaves to the caller
//! (see the module doc there): the BCAST handshake exchange, the peer map, the
//! poll loop, the outbound SESS/CHUNK send, and the decode-and-deliver trigger.
//!
//! Single-threaded, `now_ms`-driven (no goroutines/tickers) — the same synchronous
//! port style as the rest of the library. Drive it by calling `tick(now_ms)`.
//!
//! Scope: the outbound path is single-peer-correct (the RS emit planner tags each
//! dispatch with a target peer, but the `SendRsChunkFn` callback is peer-agnostic,
//! so a `sessionDrainOutboundOverQuic` call fans one session to one connection).
//! Multi-peer routing, peer authentication, and peer-disconnect events are not
//! modelled here (the same limitations ethlambda's experimental adapter carries).

const std = @import("std");
const quic = @import("quic");

const engine_mod = @import("../broadcast/engine.zig");
const Engine = engine_mod.Engine;
const EngineConfig = engine_mod.EngineConfig;
const engine_quic = @import("../broadcast/engine_quic.zig");
const EngineQuicHost = engine_quic.EngineQuicHost;
const channel_rs = @import("../broadcast/channel_rs.zig");
const ChannelRs = channel_rs.ChannelRs;
const Subscription = channel_rs.Subscription;
const SendRsChunkFn = @import("../broadcast/session_rs.zig").SendRsChunkFn;
const peer_mod = @import("../transport/eth_ec_quic_peer.zig");
const rs_init = @import("../layer/rs_init.zig");
const RsConfig = rs_init.RsConfig;
const rs_strategy = @import("../layer/rs_strategy.zig");
const broadcast_wire = @import("../wire/broadcast.zig");
const bcast_stream = @import("../wire/bcast_stream.zig");
const sess_stream = @import("../wire/sess_stream.zig");
const wire_rs = @import("../wire/rs.zig");

pub const FullMessage = channel_rs.FullMessage;

/// BCAST protocol version we announce / accept (ethp2p handshake `version`).
pub const protocol_version: u32 = 1;

/// Default UDP payload budget (matches the `eth_ec_quic` tests / defaults).
const default_max_udp_payload: u32 = 1350;

pub const BroadcastNodeConfig = struct {
    /// Local peer id announced in the BCAST handshake and used as the RS engine id.
    local_peer_id: []const u8,
    /// Listen address ("host:port") for the server endpoint. Null → the node
    /// cannot accept inbound peers (dial-only).
    listen_addr: ?[]const u8 = null,
    /// Bind address for the outbound dial (client) endpoint.
    dial_bind: []const u8 = "0.0.0.0:0",
    /// TLS server identity (PEM paths). Required when `listen_addr` is set.
    server_certificate_pem_path: ?[]const u8 = null,
    server_private_key_pem_path: ?[]const u8 = null,
    /// Accept any server certificate on dial (self-interop / tests).
    tls_insecure_skip_verify: bool = true,
    max_idle_timeout_ms: u32 = 30_000,
    max_incoming_streams: u32 = 16_384,
    max_incoming_uni_streams: u32 = 16_384,
    /// Rounds to poll while waiting for a dial handshake to complete.
    handshake_poll_rounds: u32 = 30_000,
    engine: EngineConfig = .{},
};

const PeerEntry = struct {
    host: EngineQuicHost,
    /// True once `finishBcastHandshakeRead` captured the remote peer id and the
    /// peer was registered as a member of every channel.
    ready: bool = false,
};

pub const BroadcastNode = struct {
    allocator: std.mem.Allocator,
    engine: Engine,
    listen_ep: ?*quic.QuicEndpoint,
    dial_ep: *quic.QuicEndpoint,
    /// Heap-stable peer entries (each `EngineQuicHost` is referenced by its own
    /// `PeerConn.user_data`, so it must never move).
    peers: std.ArrayListUnmanaged(*PeerEntry) = .empty,
    /// Per-channel delivery ring, keyed by channel id (keys alias `channel_ids`).
    subs: std.StringHashMapUnmanaged(*Subscription) = .empty,
    /// Owned channel-id strings (handshake `channels` list + iteration order).
    channel_ids: std.ArrayListUnmanaged([]const u8) = .empty,
    /// Optional loopback co-poll endpoint (the *other* in-process node's endpoint).
    /// Null in real deployments (each process pumps its own socket via `tick`).
    co_poll_ep: ?*quic.QuicEndpoint = null,
    handshake_poll_rounds: u32,

    pub fn init(allocator: std.mem.Allocator, cfg: BroadcastNodeConfig) !*BroadcastNode {
        const self = try allocator.create(BroadcastNode);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .engine = try Engine.init(allocator, cfg.local_peer_id, cfg.engine),
            .listen_ep = null,
            .dial_ep = undefined,
            .handshake_poll_rounds = cfg.handshake_poll_rounds,
        };
        errdefer self.engine.deinit();

        // Outbound dial endpoint (client: no server cert).
        var alpn_cli = [_][]const u8{"eth-ec-broadcast"};
        var qc_cli = quic.QuicConfig{
            .alpn = &alpn_cli,
            .allow_insecure = cfg.tls_insecure_skip_verify,
            .max_idle_timeout_ms = cfg.max_idle_timeout_ms,
            .max_udp_payload = default_max_udp_payload,
        };
        self.dial_ep = try quic.endpointInit(&self.allocator, cfg.dial_bind, &qc_cli);
        errdefer quic.endpointDeinit(self.dial_ep);

        // Inbound listen endpoint (server: cert paths required).
        if (cfg.listen_addr) |addr| {
            if (cfg.server_certificate_pem_path == null or cfg.server_private_key_pem_path == null) {
                return error.MissingServerIdentity;
            }
            var alpn_srv = [_][]const u8{"eth-ec-broadcast"};
            var qc_srv = quic.QuicConfig{
                .alpn = &alpn_srv,
                .server_cert_pem_path = cfg.server_certificate_pem_path,
                .server_private_key_pem_path = cfg.server_private_key_pem_path,
                .allow_insecure = cfg.tls_insecure_skip_verify,
                .max_idle_timeout_ms = cfg.max_idle_timeout_ms,
                .max_udp_payload = default_max_udp_payload,
                .max_incoming_streams = cfg.max_incoming_streams,
                .max_incoming_uni_streams = cfg.max_incoming_uni_streams,
            };
            self.listen_ep = try quic.endpointInit(&self.allocator, addr, &qc_srv);
        }
        return self;
    }

    pub fn deinit(self: *BroadcastNode) void {
        for (self.peers.items) |entry| {
            entry.host.deinit();
            self.allocator.destroy(entry);
        }
        self.peers.deinit(self.allocator);

        var sit = self.subs.valueIterator();
        while (sit.next()) |sub| {
            sub.*.deinit();
            self.allocator.destroy(sub.*);
        }
        self.subs.deinit(self.allocator);

        self.engine.deinit();

        if (self.listen_ep) |ep| quic.endpointDeinit(ep);
        quic.endpointDeinit(self.dial_ep);

        for (self.channel_ids.items) |id| self.allocator.free(id);
        self.channel_ids.deinit(self.allocator);

        const allocator = self.allocator;
        allocator.destroy(self);
    }

    /// Set the loopback co-poll endpoint (the other in-process node's endpoint).
    /// Must be called before `connect` / the first `tick` in loopback tests.
    pub fn setCoPollEndpoint(self: *BroadcastNode, ep: ?*quic.QuicEndpoint) void {
        self.co_poll_ep = ep;
    }

    /// Register an RS channel plus its delivery subscription. `sub_capacity`
    /// must be > 0 (an unbuffered subscription is rejected).
    pub fn addChannel(self: *BroadcastNode, channel_id: []const u8, cfg: RsConfig, sub_capacity: usize) !void {
        const ch = try self.engine.attachChannelRs(channel_id, cfg);

        const sub = try self.allocator.create(Subscription);
        errdefer self.allocator.destroy(sub);
        sub.* = try Subscription.init(self.allocator, sub_capacity);
        errdefer sub.deinit();
        try ch.subscribe(sub);

        const key = try self.allocator.dupe(u8, channel_id);
        errdefer self.allocator.free(key);
        try self.channel_ids.append(self.allocator, key);
        errdefer _ = self.channel_ids.pop();
        try self.subs.put(self.allocator, key, sub);
    }

    /// Dial a remote broadcast node and start the BCAST handshake. The peer
    /// becomes usable (`ready`) after a subsequent `tick` completes the exchange.
    pub fn connect(self: *BroadcastNode, remote_addr: []const u8, hostname: []const u8) !void {
        const conn = try quic.connect(self.dial_ep, remote_addr, hostname);
        errdefer quic.destroy(self.dial_ep, conn);

        var rounds: u32 = 0;
        while (rounds < self.handshake_poll_rounds) : (rounds += 1) {
            try quic.poll(self.dial_ep, 0);
            if (self.co_poll_ep) |p| try quic.poll(p, 0);
            if (quic.handshakeComplete(conn)) break;
        }
        if (!quic.handshakeComplete(conn)) return error.HandshakeTimeout;

        try self.registerPeer(conn, self.dial_ep);
    }

    /// Accept any inbound connections that finished their QUIC handshake and
    /// start the BCAST handshake on each. Called from `tick`.
    fn acceptInbound(self: *BroadcastNode) !void {
        const ep = self.listen_ep orelse return;
        while (quic.tryAccept(ep)) |conn| {
            try self.registerPeer(conn, ep);
        }
    }

    /// Wrap a freshly handshaked QUIC connection in an `EngineQuicHost`, wire the
    /// engine, and send our BCAST handshake open.
    fn registerPeer(self: *BroadcastNode, conn: *quic.QuicConnection, ep: *quic.QuicEndpoint) !void {
        const entry = try self.allocator.create(PeerEntry);
        errdefer self.allocator.destroy(entry);
        entry.* = .{ .host = EngineQuicHost.init(self.allocator, &self.engine, conn, ep) };
        try self.peers.append(self.allocator, entry);
        errdefer _ = self.peers.pop();

        entry.host.wireEngine();
        entry.host.setPeerEndpoint(self.co_poll_ep);

        try entry.host.peer.beginHandshake(self.co_poll_ep, .{
            .version = protocol_version,
            .channels = self.channel_ids.items,
            .peer_id = self.engine.local_peer_id,
        });
        const out = entry.host.peer.bcast_out orelse return error.MissingBcastOut;
        try quic.streamDrainWrites(out, self.coPollFor(entry), 10_000);
    }

    /// One scheduling step: pump QUIC, accept inbound, advance handshakes,
    /// decode+deliver ready relay sessions, and GC.
    pub fn tick(self: *BroadcastNode, now_ms: i64) !void {
        try quic.poll(self.dial_ep, 0);
        if (self.listen_ep) |ep| try quic.poll(ep, 0);
        if (self.co_poll_ep) |p| try quic.poll(p, 0);

        try self.acceptInbound();

        for (self.peers.items) |entry| {
            _ = entry.host.drive();
            if (!entry.ready and entry.host.peer.state == .active) {
                entry.host.finishBcastHandshakeRead() catch continue;
                self.onPeerReady(entry) catch continue;
                entry.ready = true;
            }
        }

        try self.deliverReadySessions();

        for (self.channel_ids.items) |id| {
            if (self.engine.channelRs(id)) |ch| ch.cleanup(now_ms);
        }
    }

    /// A peer finished its BCAST handshake: register its id as a member of every
    /// channel so future `publish` calls encode shards for it.
    fn onPeerReady(self: *BroadcastNode, entry: *PeerEntry) !void {
        const pid = entry.host.remote_peer_id;
        if (pid.len == 0) return error.MissingRemotePeerId;
        for (self.channel_ids.items) |id| {
            if (self.engine.channelRs(id)) |ch| try ch.addMember(pid);
        }
    }

    /// Decode any relay (consuming) session that has enough shards and deliver
    /// the reconstructed message to its subscription, then dispose it. Origin
    /// sessions (our own publishes) are skipped — no self-delivery.
    fn deliverReadySessions(self: *BroadcastNode) !void {
        var ready_ids: std.ArrayListUnmanaged([]const u8) = .empty;
        defer ready_ids.deinit(self.allocator);

        for (self.channel_ids.items) |id| {
            const ch = self.engine.channelRs(id) orelse continue;
            ready_ids.clearRetainingCapacity();

            var it = ch.sessions.iterator();
            while (it.next()) |kv| {
                const sess = kv.value_ptr.*;
                if (sess.stage == .origin) continue;
                if (sess.stage.isDecoded()) continue;
                const p = sess.strategy.progress();
                if (p.have >= p.need) {
                    ready_ids.append(self.allocator, kv.key_ptr.*) catch continue;
                }
            }

            for (ready_ids.items) |mid| {
                const decoded = ch.sessionDecode(mid) catch continue;
                self.allocator.free(decoded); // subscriber received its own copy
                ch.disposeSession(mid, "reconstructed");
            }
        }
    }

    /// Encode `payload` as an RS origin message and push its SESS open + chunks
    /// to every ready peer. Members are (re)registered first so the session
    /// snapshot includes all currently connected peers.
    pub fn publish(self: *BroadcastNode, channel_id: []const u8, message_id: []const u8, payload: []const u8) !void {
        const ch = self.engine.channelRs(channel_id) orelse return error.UnknownChannel;

        for (self.peers.items) |entry| {
            if (entry.ready) try ch.addMember(entry.host.remote_peer_id);
        }

        try ch.publish(message_id, payload);
        const strat = ch.sessionStrategy(message_id) orelse return error.MissingSession;

        const pre_bytes = try encodePreamble(self.allocator, &strat.preamble);
        defer self.allocator.free(pre_bytes);

        // SESS session_open first (so the receiver can attach the relay session
        // before its chunks arrive), then the RS shard chunks.
        var primary: ?*PeerEntry = null;
        for (self.peers.items) |entry| {
            if (!entry.ready) continue;
            try self.sendSessionOpen(entry, channel_id, message_id, pre_bytes);
            if (primary == null) primary = entry;
        }

        if (primary) |entry| {
            var ctx = SendCtx{ .node = self, .entry = entry };
            _ = try ch.sessionDrainOutboundOverQuic(message_id, &ctx, sendChunkCb);
        }
    }

    fn sendSessionOpen(
        self: *BroadcastNode,
        entry: *PeerEntry,
        channel_id: []const u8,
        message_id: []const u8,
        preamble: []const u8,
    ) !void {
        const st = try quic.streamMakeUni(entry.host.peer.conn, self.co_poll_ep);
        var aw = std.Io.Writer.Allocating.init(self.allocator);
        defer aw.deinit();
        try sess_stream.writeSessSessionOpen(&aw.writer, self.allocator, .{
            .channel = channel_id,
            .message_id = message_id,
            .preamble = preamble,
            .initial_update = &.{},
        });
        try quic.streamQueueWrite(st, aw.written());
        try quic.streamDrainWrites(st, self.coPollFor(entry), 10_000);
    }

    /// Pop the next reconstructed message for `channel_id`, or null. Ownership
    /// transfers to the caller, who frees it with `freeMessage`.
    pub fn poll(self: *BroadcastNode, channel_id: []const u8) ?FullMessage {
        const sub = self.subs.get(channel_id) orelse return null;
        return sub.pop();
    }

    /// Free a message returned by `poll`.
    pub fn freeMessage(self: *BroadcastNode, m: FullMessage) void {
        Subscription.freeMessage(self.allocator, m);
    }

    /// Local UDP port the listen endpoint bound to (0 if dial-only).
    pub fn listenPort(self: *const BroadcastNode) u16 {
        const ep = self.listen_ep orelse return 0;
        return ep.local_addr.getPort();
    }

    fn coPollFor(self: *BroadcastNode, entry: *PeerEntry) *quic.QuicEndpoint {
        return self.co_poll_ep orelse entry.host.peer.ep;
    }

    const SendCtx = struct {
        node: *BroadcastNode,
        entry: *PeerEntry,
    };

    fn sendChunkCb(
        ctx: *anyopaque,
        channel_id: []const u8,
        message_id: []const u8,
        shard_index: i32,
        payload: []const u8,
    ) anyerror!void {
        const c: *SendCtx = @ptrCast(@alignCast(ctx));
        try engine_quic.peerSendRsChunk(
            &c.entry.host.peer,
            c.node.co_poll_ep,
            channel_id,
            message_id,
            shard_index,
            payload,
        );
    }
};

/// Encode an `RsPreamble` into the SESS session_open wire preamble.
fn encodePreamble(allocator: std.mem.Allocator, pre: *const rs_strategy.RsPreamble) ![]u8 {
    const hash_slices = try allocator.alloc([]const u8, pre.chunk_hashes.len);
    defer allocator.free(hash_slices);
    for (pre.chunk_hashes, 0..) |row, i| hash_slices[i] = row;
    return wire_rs.encodePreamble(allocator, .{
        .num_data = pre.data_chunks,
        .num_parity = pre.parity_chunks,
        .length = pre.message_length,
        .hashes = hash_slices,
        .hash = &pre.message_hash,
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_certs = @import("../transport/eth_ec_quic_test_certs.zig");

const test_rs_cfg = RsConfig{
    .data_shards = 4,
    .parity_shards = 2,
    .chunk_len = 0,
    .bitmap_threshold = 0,
    .forward_multiplier = 4,
    .disable_bitmap = false,
};

test "BroadcastNode loopback: publish on A reconstructs on B" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Listener (B): bind by scanning ports.
    var listener: ?*BroadcastNode = null;
    var lport: u16 = 0;
    for (0..64) |i| {
        const p: u16 = @intCast(45500 + i);
        const addr = try std.fmt.allocPrint(alloc, "127.0.0.1:{d}", .{p});
        defer alloc.free(addr);
        listener = BroadcastNode.init(alloc, .{
            .local_peer_id = "node-b",
            .listen_addr = addr,
            .server_certificate_pem_path = "src/transport/testdata/zethp2p_cert.pem",
            .server_private_key_pem_path = "src/transport/testdata/zethp2p_key.pem",
        }) catch |err| switch (err) {
            error.AddressInUse, error.AddressNotAvailable => continue,
            else => |e| return e,
        };
        lport = p;
        break;
    }
    const node_b = listener orelse return error.NoBindPort;
    defer node_b.deinit();

    // Dialer (A): dial-only.
    const node_a = try BroadcastNode.init(alloc, .{ .local_peer_id = "node-a" });
    defer node_a.deinit();

    try node_a.addChannel("block", test_rs_cfg, 8);
    try node_b.addChannel("block", test_rs_cfg, 8);

    node_a.setCoPollEndpoint(node_b.listen_ep);
    node_b.setCoPollEndpoint(node_a.dial_ep);

    const remote = try std.fmt.allocPrint(alloc, "127.0.0.1:{d}", .{lport});
    defer alloc.free(remote);
    try node_a.connect(remote, test_certs.tls_server_name);

    // Drive both until each side has a ready peer.
    var now: i64 = 0;
    var rounds: u32 = 0;
    while (rounds < 5_000) : (rounds += 1) {
        now += 1;
        try node_a.tick(now);
        try node_b.tick(now);
        if (peersReady(node_a) and peersReady(node_b)) break;
    }
    try std.testing.expect(peersReady(node_a));
    try std.testing.expect(peersReady(node_b));

    const payload = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8 };
    try node_a.publish("block", "m1", &payload);

    // Drive until B delivers the reconstructed message.
    var got: ?FullMessage = null;
    rounds = 0;
    while (rounds < 5_000) : (rounds += 1) {
        now += 1;
        try node_a.tick(now);
        try node_b.tick(now);
        if (node_b.poll("block")) |m| {
            got = m;
            break;
        }
    }
    const m = got orelse return error.NoDelivery;
    defer node_b.freeMessage(m);
    try std.testing.expectEqualStrings("block", m.channel_id);
    try std.testing.expectEqualStrings("m1", m.message_id);
    try std.testing.expectEqualSlices(u8, &payload, m.data);
}

fn peersReady(node: *BroadcastNode) bool {
    if (node.peers.items.len == 0) return false;
    for (node.peers.items) |entry| {
        if (!entry.ready) return false;
    }
    return true;
}
