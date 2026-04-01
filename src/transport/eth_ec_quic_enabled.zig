//! QUIC + TLS when `-Denable-quic` is set (`src/transport/lsquic_quic_shim.zig` + `vendor/lsquic_zig`).

const std = @import("std");
const quic = @import("quic");
const common = @import("eth_ec_quic_common.zig");
const test_certs = @import("eth_ec_quic_test_certs.zig");
const bcast_stream = @import("../wire/bcast_stream.zig");
const sess_stream = @import("../wire/sess_stream.zig");
const protocol = @import("../wire/protocol.zig");

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
    if (config.server_certificate_der == null or config.server_private_key_der == null) {
        return error.MissingServerIdentity;
    }
    var alpn_list = [_][]const u8{common.alpn_eth_ec_broadcast};
    var qc = toQuicConfig(config, &alpn_list);
    const bind_s = try formatSocketAddr(allocator.*, address);
    defer allocator.*.free(bind_s);
    return try quic.endpointInit(allocator, bind_s, &qc);
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
        .server_certificate_der = test_certs.server_cert_der,
        .server_private_key_der = test_certs.server_key_der,
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

test "QUIC streams: BCAST handshake then SESS session_open (wire framing)" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var alloc = gpa.allocator();

    const srv_cfg = common.EthEcQuicConfig{
        .server_certificate_der = test_certs.server_cert_der,
        .server_private_key_der = test_certs.server_key_der,
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

    const cli_bcast = try quic.streamMake(conn, srv);
    var bcast_payload = std.ArrayList(u8).empty;
    defer bcast_payload.deinit(alloc);
    {
        const w = bcast_payload.writer(alloc);
        try bcast_stream.writeBcastHandshakeOpen(w, alloc, .{
            .version = 1,
            .channels = &.{ "blocks", "atts" },
            .peer_id = "peer1",
        });
    }
    try quic.streamQueueWrite(cli_bcast, bcast_payload.items);
    try quic.streamDrainWrites(cli_bcast, srv, 10_000);

    const srv_bcast = try acceptIncomingQuicStream(sc, srv, client_ep);
    try waitQuicStreamBytes(srv_bcast, srv, client_ep, bcast_payload.items.len, 10_000);
    try std.testing.expectEqualSlices(u8, bcast_payload.items, quic.streamReadSlice(srv_bcast));
    const bcast_copy = try alloc.dupe(u8, quic.streamReadSlice(srv_bcast));
    defer alloc.free(bcast_copy);
    var bcast_fbs = std.io.fixedBufferStream(bcast_copy);
    var hs_owned = try bcast_stream.readBcastPeerHandshake(alloc, bcast_fbs.reader());
    defer hs_owned.deinit(alloc);
    switch (hs_owned) {
        .peer_handshake => |h| {
            try std.testing.expectEqual(@as(u32, 1), h.version);
            try std.testing.expectEqualStrings("peer1", h.peer_id);
        },
        else => unreachable,
    }

    const cli_sess = try quic.streamMake(conn, srv);
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

    const srv_sess = try acceptIncomingQuicStream(sc, srv, client_ep);
    try waitQuicStreamBytes(srv_sess, srv, client_ep, sess_payload.items.len, 10_000);
    try std.testing.expectEqualSlices(u8, sess_payload.items, quic.streamReadSlice(srv_sess));
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
