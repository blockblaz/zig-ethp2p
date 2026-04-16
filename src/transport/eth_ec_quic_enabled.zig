//! QUIC + TLS implementation (`src/transport/zquic_quic_shim.zig` + [zquic](https://github.com/ch4r10t33r/zquic)).

const std = @import("std");
const quic = @import("quic");
const common = @import("eth_ec_quic_common.zig");
const test_certs = @import("eth_ec_quic_test_certs.zig");
const bcast_stream = @import("../wire/bcast_stream.zig");
const sess_stream = @import("../wire/sess_stream.zig");
const protocol = @import("../wire/protocol.zig");
const chunk_stream = @import("../wire/chunk_stream.zig");
const wire_rs = @import("../wire/rs.zig");
const Engine = @import("../broadcast/engine.zig").Engine;
const engine_quic = @import("../broadcast/engine_quic.zig");
const SendRsChunkFn = @import("../broadcast/session_rs.zig").SendRsChunkFn;
const peer_mod = @import("eth_ec_quic_peer.zig");
const rs_init = @import("../layer/rs_init.zig");
const rs_strategy = @import("../layer/rs_strategy.zig");

fn acceptIncomingQuicStream(
    conn: *quic.QuicConnection,
    local: *quic.QuicEndpoint,
    peer: *quic.QuicEndpoint,
) anyerror!*quic.QuicStream {
    var budget: u32 = 10_000;
    while (budget > 0) : (budget -= 1) {
        if (quic.tryAcceptIncomingStream(conn)) |st| return st;
        try quic.poll(local, 0);
        try quic.poll(peer, 0);
    }
    return error.QuicAcceptStreamTimeout;
}

fn acceptIncomingQuicUniStream(
    conn: *quic.QuicConnection,
    local: *quic.QuicEndpoint,
    peer: *quic.QuicEndpoint,
) anyerror!*quic.QuicStream {
    var budget: u32 = 10_000;
    while (budget > 0) : (budget -= 1) {
        if (quic.tryAcceptIncomingUniStream(conn)) |st| return st;
        try quic.poll(local, 0);
        try quic.poll(peer, 0);
    }
    return error.QuicAcceptUniStreamTimeout;
}

fn waitQuicStreamBytes(
    st: *quic.QuicStream,
    local: *quic.QuicEndpoint,
    peer: *quic.QuicEndpoint,
    need: usize,
    max_poll_rounds: u32,
) !void {
    var i: u32 = 0;
    while (quic.streamReadSlice(st).len < need and i < max_poll_rounds) : (i += 1) {
        try quic.poll(local, 0);
        try quic.poll(peer, 0);
    }
    if (quic.streamReadSlice(st).len < need) return error.QuicTestReadTimeout;
}

fn maxIdleTimeoutMs(ns: u64) u32 {
    const ms = ns / std.time.ns_per_ms;
    return @intCast(@min(ms, @as(u64, std.math.maxInt(u32))));
}

fn formatSocketAddr(allocator: std.mem.Allocator, address: common.ListenAddress) std.mem.Allocator.Error![]const u8 {
    if (std.mem.indexOfScalar(u8, address.host, ':') != null) {
        return try std.fmt.allocPrint(allocator, "[{s}]:{d}", .{ address.host, address.port });
    }
    return try std.fmt.allocPrint(allocator, "{s}:{d}", .{ address.host, address.port });
}

fn toQuicConfig(
    config: common.EthEcQuicConfig,
    alpn_list: *const [1][]const u8,
) quic.QuicConfig {
    return .{
        .alpn = alpn_list,
        .inline_server_cert_der = config.server_certificate_der,
        .inline_server_priv_p256 = config.server_private_key_der,
        .server_cert_pem_path = config.server_certificate_pem_path,
        .server_private_key_pem_path = config.server_private_key_pem_path,
        .allow_insecure = config.tls_insecure_skip_verify,
        .max_idle_timeout_ms = maxIdleTimeoutMs(config.max_idle_timeout_ns),
        .max_udp_payload = 1350,
    };
}

pub fn listenImpl(
    allocator: *std.mem.Allocator,
    config: common.EthEcQuicConfig,
    address: common.ListenAddress,
) !*quic.QuicEndpoint {
    if (config.server_certificate_pem_path == null or config.server_private_key_pem_path == null) {
        return error.MissingServerIdentity;
    }
    var alpn_list = [_][]const u8{common.alpn_eth_ec_broadcast};
    var qc = toQuicConfig(config, &alpn_list);
    const bind_s = try formatSocketAddr(allocator.*, address);
    defer allocator.*.free(bind_s);
    return try quic.endpointInit(allocator, bind_s, &qc);
}

/// Create a QUIC server endpoint on an already-bound external socket fd.
pub fn listenImplFromFd(
    allocator: *std.mem.Allocator,
    fd: std.posix.fd_t,
    local_addr: std.net.Address,
    config: common.EthEcQuicConfig,
) !*quic.QuicEndpoint {
    if (config.server_certificate_pem_path == null or config.server_private_key_pem_path == null) {
        return error.MissingServerIdentity;
    }
    var alpn_list = [_][]const u8{common.alpn_eth_ec_broadcast};
    var qc = toQuicConfig(config, &alpn_list);
    return try quic.endpointInitFromFd(allocator, fd, local_addr, &qc);
}

pub fn dialImpl(
    allocator: *std.mem.Allocator,
    config: common.EthEcQuicConfig,
    remote: common.ListenAddress,
) !void {
    var alpn_list = [_][]const u8{common.alpn_eth_ec_broadcast};
    var client_cfg = quic.QuicConfig{
        .alpn = &alpn_list,
        .allow_insecure = config.tls_insecure_skip_verify,
        .max_idle_timeout_ms = maxIdleTimeoutMs(config.max_idle_timeout_ns),
        .max_udp_payload = 1350,
    };
    const client_ep = try quic.endpointInit(allocator, "127.0.0.1:0", &client_cfg);
    defer quic.endpointDeinit(client_ep);

    const remote_s = try formatSocketAddr(allocator.*, remote);
    defer allocator.*.free(remote_s);

    const conn = try quic.connect(client_ep, remote_s, remote.host);
    errdefer quic.destroy(client_ep, conn);

    var rounds: u32 = 0;
    while (rounds < 30_000) : (rounds += 1) {
        try quic.poll(client_ep, 0);
        if (quic.handshakeComplete(conn)) break;
    }
    if (!quic.handshakeComplete(conn)) return error.HandshakeTimeout;

    const negotiated = quic.getNegotiatedAlpn(conn) orelse return error.MissingAlpn;
    if (!std.mem.eql(u8, negotiated, common.alpn_eth_ec_broadcast)) return error.AlpnMismatch;

    quic.destroy(client_ep, conn);
}

test "QUIC listen + dial, TLS handshake, ALPN eth-ec-broadcast" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    const srv_cfg = common.EthEcQuicConfig{
        .server_certificate_pem_path = "src/transport/testdata/zethp2p_cert.pem",
        .server_private_key_pem_path = "src/transport/testdata/zethp2p_key.pem",
        .tls_insecure_skip_verify = true,
    };
    var alpn_srv = [_][]const u8{common.alpn_eth_ec_broadcast};
    var qc_srv = toQuicConfig(srv_cfg, &alpn_srv);
    var server_ep: ?*quic.QuicEndpoint = null;
    var sport: u16 = 0;
    for (0..64) |i| {
        const p: u16 = @intCast(45100 + i);
        const bind_s = try std.fmt.allocPrint(alloc, "127.0.0.1:{d}", .{p});
        defer alloc.free(bind_s);
        server_ep = quic.endpointInit(&alloc, bind_s, &qc_srv) catch |err| switch (err) {
            error.AddressInUse, error.AddressNotAvailable => continue,
            else => |e| return e,
        };
        sport = p;
        break;
    }
    const srv = server_ep orelse return error.NoBindPort;
    defer quic.endpointDeinit(srv);

    const client_cfg = common.EthEcQuicConfig{
        .tls_insecure_skip_verify = true,
    };
    var alpn_cli = [_][]const u8{common.alpn_eth_ec_broadcast};
    var qc_cli = quic.QuicConfig{
        .alpn = &alpn_cli,
        .allow_insecure = client_cfg.tls_insecure_skip_verify,
        .max_idle_timeout_ms = maxIdleTimeoutMs(client_cfg.max_idle_timeout_ns),
        .max_udp_payload = 1350,
    };
    const client_ep = try quic.endpointInit(&alloc, "127.0.0.1:0", &qc_cli);
    defer quic.endpointDeinit(client_ep);

    const remote_s = try std.fmt.allocPrint(alloc, "127.0.0.1:{d}", .{sport});
    defer alloc.free(remote_s);

    const conn = try quic.connect(client_ep, remote_s, test_certs.tls_server_name);
    errdefer quic.destroy(client_ep, conn);

    var server_conn: ?*quic.QuicConnection = null;
    var rounds: u32 = 0;
    while (rounds < 30_000) : (rounds += 1) {
        try quic.poll(srv, 0);
        try quic.poll(client_ep, 0);
        if (server_conn == null) {
            server_conn = quic.tryAccept(srv);
        }
        if (quic.handshakeComplete(conn)) {
            if (server_conn) |sc| {
                if (quic.handshakeComplete(sc)) break;
            }
        }
    }

    const sc = server_conn orelse return error.MissingServerConnection;
    try std.testing.expect(quic.handshakeComplete(conn));
    try std.testing.expect(quic.handshakeComplete(sc));

    const alpn_c = quic.getNegotiatedAlpn(conn) orelse return error.MissingAlpn;
    const alpn_s = quic.getNegotiatedAlpn(sc) orelse return error.MissingAlpn;
    try std.testing.expectEqualStrings(common.alpn_eth_ec_broadcast, alpn_c);
    try std.testing.expectEqualStrings(common.alpn_eth_ec_broadcast, alpn_s);

    quic.destroy(srv, sc);
    quic.destroy(client_ep, conn);
}

// Matches the symmetric BCAST handshake in peer.go:
//   Both sides concurrently call OpenUniStream() and write PROTOCOL_BCAST + Handshake.
//   Both sides concurrently call AcceptUniStream() to receive the peer's stream.
// In Zig's poll-driven model we do this sequentially but interleave both sides before
// any reads so neither blocks waiting for the other.
test "QUIC UNI streams: symmetric BCAST handshake + SESS session_open (wire framing)" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    const srv_cfg = common.EthEcQuicConfig{
        .server_certificate_pem_path = "src/transport/testdata/zethp2p_cert.pem",
        .server_private_key_pem_path = "src/transport/testdata/zethp2p_key.pem",
        .tls_insecure_skip_verify = true,
    };
    var alpn_srv = [_][]const u8{common.alpn_eth_ec_broadcast};
    var qc_srv = toQuicConfig(srv_cfg, &alpn_srv);
    var server_ep: ?*quic.QuicEndpoint = null;
    var sport: u16 = 0;
    for (0..64) |i| {
        const p: u16 = @intCast(45200 + i);
        const bind_s = try std.fmt.allocPrint(alloc, "127.0.0.1:{d}", .{p});
        defer alloc.free(bind_s);
        server_ep = quic.endpointInit(&alloc, bind_s, &qc_srv) catch |err| switch (err) {
            error.AddressInUse, error.AddressNotAvailable => continue,
            else => |e| return e,
        };
        sport = p;
        break;
    }
    const srv = server_ep orelse return error.NoBindPort;
    defer quic.endpointDeinit(srv);

    var alpn_cli = [_][]const u8{common.alpn_eth_ec_broadcast};
    var qc_cli = quic.QuicConfig{
        .alpn = &alpn_cli,
        .allow_insecure = true,
        .max_idle_timeout_ms = maxIdleTimeoutMs(common.EthEcQuicConfig.default().max_idle_timeout_ns),
        .max_udp_payload = 1350,
    };
    const client_ep = try quic.endpointInit(&alloc, "127.0.0.1:0", &qc_cli);
    defer quic.endpointDeinit(client_ep);

    const remote_s = try std.fmt.allocPrint(alloc, "127.0.0.1:{d}", .{sport});
    defer alloc.free(remote_s);

    const conn = try quic.connect(client_ep, remote_s, test_certs.tls_server_name);
    errdefer quic.destroy(client_ep, conn);

    var server_conn: ?*quic.QuicConnection = null;
    var rounds: u32 = 0;
    while (rounds < 30_000) : (rounds += 1) {
        try quic.poll(srv, 0);
        try quic.poll(client_ep, 0);
        if (server_conn == null) server_conn = quic.tryAccept(srv);
        if (quic.handshakeComplete(conn)) {
            if (server_conn) |sc| {
                if (quic.handshakeComplete(sc)) break;
            }
        }
    }
    const sc = server_conn orelse return error.MissingServerConnection;
    try std.testing.expect(quic.handshakeComplete(conn));
    try std.testing.expect(quic.handshakeComplete(sc));

    // --- BCAST symmetric handshake (UNI streams) ---
    // Both sides open their outbound BCAST UNI stream before either reads,
    // matching peer.go's concurrent goroutine pattern.

    const cli_bcast_out = try quic.streamMakeUni(conn, srv);
    const srv_bcast_out = try quic.streamMakeUni(sc, client_ep);

    var cli_bcast_payload = std.ArrayList(u8).empty;
    defer cli_bcast_payload.deinit(alloc);
    {
        const w = cli_bcast_payload.writer(alloc);
        try bcast_stream.writeBcastHandshakeOpen(w, alloc, .{
            .version = 1,
            .channels = &.{ "blocks", "atts" },
            .peer_id = "client-peer",
        });
    }
    try quic.streamQueueWrite(cli_bcast_out, cli_bcast_payload.items);
    try quic.streamDrainWrites(cli_bcast_out, srv, 10_000);

    var srv_bcast_payload = std.ArrayList(u8).empty;
    defer srv_bcast_payload.deinit(alloc);
    {
        const w = srv_bcast_payload.writer(alloc);
        try bcast_stream.writeBcastHandshakeOpen(w, alloc, .{
            .version = 1,
            .channels = &.{"chunks"},
            .peer_id = "server-peer",
        });
    }
    try quic.streamQueueWrite(srv_bcast_out, srv_bcast_payload.items);
    try quic.streamDrainWrites(srv_bcast_out, client_ep, 10_000);

    // Accept the peer's inbound BCAST UNI stream on each side.
    const srv_bcast_in = try acceptIncomingQuicUniStream(sc, srv, client_ep);
    const cli_bcast_in = try acceptIncomingQuicUniStream(conn, client_ep, srv);

    try waitQuicStreamBytes(srv_bcast_in, srv, client_ep, cli_bcast_payload.items.len, 10_000);
    try waitQuicStreamBytes(cli_bcast_in, client_ep, srv, srv_bcast_payload.items.len, 10_000);

    try std.testing.expectEqualSlices(u8, cli_bcast_payload.items, quic.streamReadSlice(srv_bcast_in));
    try std.testing.expectEqualSlices(u8, srv_bcast_payload.items, quic.streamReadSlice(cli_bcast_in));

    // Decode the client's BCAST handshake as seen by the server.
    const bcast_copy = try alloc.dupe(u8, quic.streamReadSlice(srv_bcast_in));
    defer alloc.free(bcast_copy);
    var bcast_fbs = std.io.fixedBufferStream(bcast_copy);
    var hs_owned = try bcast_stream.readBcastPeerHandshake(alloc, bcast_fbs.reader());
    defer hs_owned.deinit(alloc);
    switch (hs_owned) {
        .peer_handshake => |h| {
            try std.testing.expectEqual(@as(u32, 1), h.version);
            try std.testing.expectEqualStrings("client-peer", h.peer_id);
        },
        else => unreachable,
    }

    // --- SESS UNI stream (peer_ctrl.go handleSessionOpen) ---
    // Client opens a SESS UNI stream and writes session_open.
    const cli_sess = try quic.streamMakeUni(conn, srv);
    var sess_payload = std.ArrayList(u8).empty;
    defer sess_payload.deinit(alloc);
    {
        const w = sess_payload.writer(alloc);
        try sess_stream.writeSessSessionOpen(w, alloc, .{
            .channel = "ch1",
            .message_id = "mid",
            .preamble = &.{ 1, 2, 3 },
            .initial_update = &.{ 4, 5 },
        });
    }
    try quic.streamQueueWrite(cli_sess, sess_payload.items);
    try quic.streamDrainWrites(cli_sess, srv, 10_000);

    // Server accepts the SESS UNI stream (peer_in.go runAcceptLoop).
    const srv_sess = try acceptIncomingQuicUniStream(sc, srv, client_ep);
    try waitQuicStreamBytes(srv_sess, srv, client_ep, sess_payload.items.len, 10_000);
    try std.testing.expectEqualSlices(u8, sess_payload.items, quic.streamReadSlice(srv_sess));

    // Decode SESS session_open frame.
    const sess_copy = try alloc.dupe(u8, quic.streamReadSlice(srv_sess));
    defer alloc.free(sess_copy);
    var sess_fbs = std.io.fixedBufferStream(sess_copy);
    const sess_r = sess_fbs.reader();
    const sel = try protocol.readSelectorByte(sess_r);
    try std.testing.expectEqual(protocol.Protocol.sess, sel);
    var open_owned = try sess_stream.readSessSessionOpenAfterSelector(alloc, sess_r);
    defer open_owned.deinit(alloc);
    switch (open_owned) {
        .session_open => |o| {
            try std.testing.expectEqualStrings("ch1", o.channel);
            try std.testing.expectEqualStrings("mid", o.message_id);
        },
        else => unreachable,
    }

    quic.destroy(srv, sc);
    quic.destroy(client_ep, conn);
}

// EngineQuicHost: inbound SESS/CHUNK into Engine / ChannelRs (issue #37).
test "QUIC EngineQuicHost SESS session_open + CHUNK relay ingest" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    const srv_cfg = common.EthEcQuicConfig{
        .server_certificate_pem_path = "src/transport/testdata/zethp2p_cert.pem",
        .server_private_key_pem_path = "src/transport/testdata/zethp2p_key.pem",
        .tls_insecure_skip_verify = true,
    };
    var alpn_srv = [_][]const u8{common.alpn_eth_ec_broadcast};
    var qc_srv = toQuicConfig(srv_cfg, &alpn_srv);
    var server_ep: ?*quic.QuicEndpoint = null;
    var sport: u16 = 0;
    for (0..64) |i| {
        const p: u16 = @intCast(45300 + i);
        const bind_s = try std.fmt.allocPrint(alloc, "127.0.0.1:{d}", .{p});
        defer alloc.free(bind_s);
        server_ep = quic.endpointInit(&alloc, bind_s, &qc_srv) catch |err| switch (err) {
            error.AddressInUse, error.AddressNotAvailable => continue,
            else => |e| return e,
        };
        sport = p;
        break;
    }
    const srv = server_ep orelse return error.NoBindPort;
    defer quic.endpointDeinit(srv);

    var alpn_cli = [_][]const u8{common.alpn_eth_ec_broadcast};
    var qc_cli = quic.QuicConfig{
        .alpn = &alpn_cli,
        .allow_insecure = true,
        .max_idle_timeout_ms = maxIdleTimeoutMs(common.EthEcQuicConfig.default().max_idle_timeout_ns),
        .max_udp_payload = 1350,
    };
    const client_ep = try quic.endpointInit(&alloc, "127.0.0.1:0", &qc_cli);
    defer quic.endpointDeinit(client_ep);

    const remote_s = try std.fmt.allocPrint(alloc, "127.0.0.1:{d}", .{sport});
    defer alloc.free(remote_s);

    const conn = try quic.connect(client_ep, remote_s, test_certs.tls_server_name);
    errdefer quic.destroy(client_ep, conn);

    var server_conn: ?*quic.QuicConnection = null;
    var rounds: u32 = 0;
    while (rounds < 30_000) : (rounds += 1) {
        try quic.poll(srv, 0);
        try quic.poll(client_ep, 0);
        if (server_conn == null) server_conn = quic.tryAccept(srv);
        if (quic.handshakeComplete(conn)) {
            if (server_conn) |c| {
                if (quic.handshakeComplete(c)) break;
            }
        }
    }
    const sc = server_conn orelse return error.MissingServerConnection;
    try std.testing.expect(quic.handshakeComplete(conn));
    try std.testing.expect(quic.handshakeComplete(sc));

    const cfg = rs_init.RsConfig{
        .data_shards = 4,
        .parity_shards = 2,
        .chunk_len = 0,
        .bitmap_threshold = 0,
        .forward_multiplier = 4,
        .disable_bitmap = false,
    };

    var engine = try Engine.init(alloc, "server-local", .{});
    defer engine.deinit();

    const ch = try engine.attachChannelRs("ch1", cfg);
    try ch.addMember("client-peer");

    var host = engine_quic.EngineQuicHost.init(alloc, &engine, sc, srv);
    defer host.deinit();
    host.wireEngine();
    host.setPeerEndpoint(client_ep);

    var cli_pc = peer_mod.PeerConn.init(alloc, conn, client_ep);

    try host.peer.beginHandshake(client_ep, .{
        .version = 1,
        .channels = &.{"ch1"},
        .peer_id = "server-peer",
    });
    try cli_pc.beginHandshake(srv, .{
        .version = 1,
        .channels = &.{"ch1"},
        .peer_id = "client-peer",
    });

    var srv_bcast_payload = std.ArrayList(u8).empty;
    defer srv_bcast_payload.deinit(alloc);
    {
        const w = srv_bcast_payload.writer(alloc);
        try bcast_stream.writeBcastHandshakeOpen(w, alloc, .{
            .version = 1,
            .channels = &.{"ch1"},
            .peer_id = "server-peer",
        });
    }
    try quic.streamQueueWrite(host.peer.bcast_out.?, srv_bcast_payload.items);
    try quic.streamDrainWrites(host.peer.bcast_out.?, client_ep, 10_000);

    var cli_bcast_payload = std.ArrayList(u8).empty;
    defer cli_bcast_payload.deinit(alloc);
    {
        const w = cli_bcast_payload.writer(alloc);
        try bcast_stream.writeBcastHandshakeOpen(w, alloc, .{
            .version = 1,
            .channels = &.{"ch1"},
            .peer_id = "client-peer",
        });
    }
    try quic.streamQueueWrite(cli_pc.bcast_out.?, cli_bcast_payload.items);
    try quic.streamDrainWrites(cli_pc.bcast_out.?, srv, 10_000);

    rounds = 0;
    while (rounds < 30_000) : (rounds += 1) {
        try quic.poll(srv, 0);
        try quic.poll(client_ep, 0);
        _ = host.peer.drive();
        _ = cli_pc.drive();
        if (host.peer.state == .active and cli_pc.state == .active) break;
    }
    try std.testing.expectEqual(peer_mod.PeerConnState.active, host.peer.state);
    try std.testing.expectEqual(peer_mod.PeerConnState.active, cli_pc.state);

    try host.finishBcastHandshakeRead();
    try std.testing.expectEqualStrings("client-peer", host.remote_peer_id);

    const payload = [_]u8{ 9, 8, 7, 6, 5 };
    var origin = try rs_strategy.RsStrategy.newOrigin(alloc, cfg, &payload);
    defer origin.deinit();

    const hash_slices = try alloc.alloc([]const u8, origin.preamble.chunk_hashes.len);
    defer alloc.free(hash_slices);
    for (origin.preamble.chunk_hashes, 0..) |row, i| {
        hash_slices[i] = row;
    }
    const pre_bytes = try wire_rs.encodePreamble(alloc, .{
        .num_data = origin.preamble.data_chunks,
        .num_parity = origin.preamble.parity_chunks,
        .length = origin.preamble.message_length,
        .hashes = hash_slices,
        .hash = &origin.preamble.message_hash,
    });
    defer alloc.free(pre_bytes);

    const cli_sess = try quic.streamMakeUni(conn, srv);
    var sess_pl = std.ArrayList(u8).empty;
    defer sess_pl.deinit(alloc);
    {
        const w = sess_pl.writer(alloc);
        try sess_stream.writeSessSessionOpen(w, alloc, .{
            .channel = "ch1",
            .message_id = "m1",
            .preamble = pre_bytes,
            .initial_update = &.{},
        });
    }
    try quic.streamQueueWrite(cli_sess, sess_pl.items);
    try quic.streamDrainWrites(cli_sess, srv, 10_000);

    rounds = 0;
    while (rounds < 20_000) : (rounds += 1) {
        try quic.poll(srv, 0);
        try quic.poll(client_ep, 0);
        _ = host.peer.drive();
        if (ch.sessionStrategy("m1") != null) break;
    }
    try std.testing.expect(ch.sessionStrategy("m1") != null);

    const cli_chunk = try quic.streamMakeUni(conn, srv);
    var chunk_pl = std.ArrayList(u8).empty;
    defer chunk_pl.deinit(alloc);
    {
        const w = chunk_pl.writer(alloc);
        try chunk_stream.writeRsShardChunk(w, alloc, "ch1", "m1", 0, origin.chunks[0]);
    }
    try quic.streamQueueWrite(cli_chunk, chunk_pl.items);
    try quic.streamDrainWrites(cli_chunk, srv, 10_000);

    rounds = 0;
    while (rounds < 20_000) : (rounds += 1) {
        try quic.poll(srv, 0);
        try quic.poll(client_ep, 0);
        _ = host.peer.drive();
        const st = ch.sessionStrategy("m1") orelse break;
        if (st.progress().have > 0) break;
    }

    const st_final = ch.sessionStrategy("m1") orelse return error.MissingSession;
    try std.testing.expect(st_final.progress().have > 0);

    quic.destroy(srv, sc);
    quic.destroy(client_ep, conn);
}

// Origin outbound RS chunks over QUIC (#48): peerSendRsChunk + sessionDrainOutboundOverQuic.
test "QUIC origin RS outbound CHUNK (peerSendRsChunk + sessionDrainOutboundOverQuic)" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    const srv_cfg = common.EthEcQuicConfig{
        .server_certificate_pem_path = "src/transport/testdata/zethp2p_cert.pem",
        .server_private_key_pem_path = "src/transport/testdata/zethp2p_key.pem",
        .tls_insecure_skip_verify = true,
    };
    var alpn_srv = [_][]const u8{common.alpn_eth_ec_broadcast};
    var qc_srv = toQuicConfig(srv_cfg, &alpn_srv);
    var server_ep: ?*quic.QuicEndpoint = null;
    var sport: u16 = 0;
    for (0..64) |i| {
        const p: u16 = @intCast(45400 + i);
        const bind_s = try std.fmt.allocPrint(alloc, "127.0.0.1:{d}", .{p});
        defer alloc.free(bind_s);
        server_ep = quic.endpointInit(&alloc, bind_s, &qc_srv) catch |err| switch (err) {
            error.AddressInUse, error.AddressNotAvailable => continue,
            else => |e| return e,
        };
        sport = p;
        break;
    }
    const srv = server_ep orelse return error.NoBindPort;
    defer quic.endpointDeinit(srv);

    var alpn_cli = [_][]const u8{common.alpn_eth_ec_broadcast};
    var qc_cli = quic.QuicConfig{
        .alpn = &alpn_cli,
        .allow_insecure = true,
        .max_idle_timeout_ms = maxIdleTimeoutMs(common.EthEcQuicConfig.default().max_idle_timeout_ns),
        .max_udp_payload = 1350,
    };
    const client_ep = try quic.endpointInit(&alloc, "127.0.0.1:0", &qc_cli);
    defer quic.endpointDeinit(client_ep);

    const remote_s = try std.fmt.allocPrint(alloc, "127.0.0.1:{d}", .{sport});
    defer alloc.free(remote_s);

    const conn = try quic.connect(client_ep, remote_s, test_certs.tls_server_name);
    errdefer quic.destroy(client_ep, conn);

    var server_conn: ?*quic.QuicConnection = null;
    var rounds: u32 = 0;
    while (rounds < 30_000) : (rounds += 1) {
        try quic.poll(srv, 0);
        try quic.poll(client_ep, 0);
        if (server_conn == null) server_conn = quic.tryAccept(srv);
        if (quic.handshakeComplete(conn)) {
            if (server_conn) |c| {
                if (quic.handshakeComplete(c)) break;
            }
        }
    }
    const sc = server_conn orelse return error.MissingServerConnection;
    try std.testing.expect(quic.handshakeComplete(conn));
    try std.testing.expect(quic.handshakeComplete(sc));

    const cfg = rs_init.RsConfig{
        .data_shards = 4,
        .parity_shards = 2,
        .chunk_len = 0,
        .bitmap_threshold = 0,
        .forward_multiplier = 4,
        .disable_bitmap = false,
    };

    var engine = try Engine.init(alloc, "server-local", .{});
    defer engine.deinit();

    const ch = try engine.attachChannelRs("ch1", cfg);
    try ch.addMember("client-peer");

    var host = engine_quic.EngineQuicHost.init(alloc, &engine, sc, srv);
    defer host.deinit();
    host.wireEngine();
    host.setPeerEndpoint(client_ep);

    var cli_pc = peer_mod.PeerConn.init(alloc, conn, client_ep);

    try host.peer.beginHandshake(client_ep, .{
        .version = 1,
        .channels = &.{"ch1"},
        .peer_id = "server-peer",
    });
    try cli_pc.beginHandshake(srv, .{
        .version = 1,
        .channels = &.{"ch1"},
        .peer_id = "client-peer",
    });

    var srv_bcast_payload = std.ArrayList(u8).empty;
    defer srv_bcast_payload.deinit(alloc);
    {
        const w = srv_bcast_payload.writer(alloc);
        try bcast_stream.writeBcastHandshakeOpen(w, alloc, .{
            .version = 1,
            .channels = &.{"ch1"},
            .peer_id = "server-peer",
        });
    }
    try quic.streamQueueWrite(host.peer.bcast_out.?, srv_bcast_payload.items);
    try quic.streamDrainWrites(host.peer.bcast_out.?, client_ep, 10_000);

    var cli_bcast_payload = std.ArrayList(u8).empty;
    defer cli_bcast_payload.deinit(alloc);
    {
        const w = cli_bcast_payload.writer(alloc);
        try bcast_stream.writeBcastHandshakeOpen(w, alloc, .{
            .version = 1,
            .channels = &.{"ch1"},
            .peer_id = "client-peer",
        });
    }
    try quic.streamQueueWrite(cli_pc.bcast_out.?, cli_bcast_payload.items);
    try quic.streamDrainWrites(cli_pc.bcast_out.?, srv, 10_000);

    rounds = 0;
    while (rounds < 30_000) : (rounds += 1) {
        try quic.poll(srv, 0);
        try quic.poll(client_ep, 0);
        _ = host.peer.drive();
        _ = cli_pc.drive();
        if (host.peer.state == .active and cli_pc.state == .active) break;
    }
    try std.testing.expectEqual(peer_mod.PeerConnState.active, host.peer.state);
    try std.testing.expectEqual(peer_mod.PeerConnState.active, cli_pc.state);

    try host.finishBcastHandshakeRead();
    try std.testing.expectEqualStrings("client-peer", host.remote_peer_id);

    const payload = [_]u8{ 9, 8, 7, 6, 5 };
    try ch.publish("m1", &payload);

    const SendCtx = struct {
        pc: *peer_mod.PeerConn,
        poll_peer: *quic.QuicEndpoint,
    };
    var send_ctx = SendCtx{ .pc = &host.peer, .poll_peer = client_ep };

    const send_chunk: SendRsChunkFn = struct {
        fn call(
            ctx: *anyopaque,
            channel_id: []const u8,
            message_id: []const u8,
            index: i32,
            data: []const u8,
        ) !void {
            const c: *SendCtx = @ptrCast(@alignCast(ctx));
            try engine_quic.peerSendRsChunk(c.pc, c.poll_peer, channel_id, message_id, index, data);
        }
    }.call;

    const n = try ch.sessionDrainOutboundOverQuic("m1", &send_ctx, send_chunk);
    try std.testing.expect(n > 0);

    const strat = ch.sessionStrategy("m1") orelse return error.MissingSession;

    const ust = try acceptIncomingQuicUniStream(conn, client_ep, srv);
    var last_len: usize = 0;
    var stable: u32 = 0;
    var pb: u32 = 0;
    while (pb < 10_000) : (pb += 1) {
        try quic.poll(client_ep, 0);
        try quic.poll(srv, 0);
        const rlen = quic.streamReadSlice(ust).len;
        if (rlen == last_len and rlen > 0) {
            stable += 1;
            if (stable >= 2) break;
        } else {
            stable = 0;
            last_len = rlen;
        }
    }
    const raw_in = quic.streamReadSlice(ust);
    try std.testing.expect(raw_in.len > 0);

    var fbs = std.io.fixedBufferStream(raw_in);
    var cin = try chunk_stream.readChunkStream(alloc, fbs.reader());
    defer cin.deinit(alloc);
    try std.testing.expectEqualStrings("ch1", cin.header.channel);
    try std.testing.expectEqualStrings("m1", cin.header.message_id);
    const ident = try wire_rs.decodeChunkIdent(alloc, cin.header.chunk_id);
    const idx: usize = @intCast(ident.index);
    try std.testing.expect(idx < strat.chunks.len);
    try std.testing.expectEqualSlices(u8, strat.chunks[idx], cin.payload);

    quic.destroy(srv, sc);
    quic.destroy(client_ep, conn);
}
