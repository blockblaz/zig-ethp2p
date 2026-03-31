//! QUIC stream adapters for `wire.*` (BCAST / SESS / CHUNK) when `-Denable-quic` is set.
//! Maps devnw `quic.readStream` / `quic.writeStream` plus `quic.poll` to the `readNoEof` /
//! `writeAll` interface used by `wire/bcast_stream.zig`, `wire/sess_stream.zig`, and `wire/chunk_stream.zig`.

const std = @import("std");
const quic = @import("quic");

const bcast_stream = @import("../wire/bcast_stream.zig");
const sess_stream = @import("../wire/sess_stream.zig");
const chunk_stream = @import("../wire/chunk_stream.zig");
const protocol = @import("../wire/protocol.zig");
const common = @import("eth_ec_quic_common.zig");
const test_certs = @import("eth_ec_quic_test_certs.zig");

/// Drives local and peer QUIC endpoints so datagrams and stream data make progress.
pub const QuicIoPair = struct {
    local: *quic.QuicEndpoint,
    peer: *quic.QuicEndpoint,

    pub fn drive(self: *const QuicIoPair) !void {
        try quic.poll(self.local, 0);
        try quic.poll(self.peer, 0);
    }
};

pub const QuicStreamWriter = struct {
    /// QUIC I/O can surface many OS and stack errors; use `anyerror` so we avoid pulling the full `quic.poll` / `quic.writeStream` error sets into this module’s comptime graph (very slow to analyze).
    pub const Error = anyerror;

    io: *const QuicIoPair,
    conn: *quic.QuicConnection,
    sid: quic.QuicStreamId,

    pub fn writeAll(self: *QuicStreamWriter, chunk: []const u8) Error!void {
        var off: usize = 0;
        while (off < chunk.len) {
            try self.io.drive();
            const n = quic.writeStream(self.conn, self.sid, chunk[off..], false) catch |err| switch (err) {
                error.FlowControlBlocked => continue,
                else => |e| return e,
            };
            if (n == 0) continue;
            off += n;
        }
    }
};

pub const QuicStreamReader = struct {
    io: *const QuicIoPair,
    conn: *quic.QuicConnection,
    sid: quic.QuicStreamId,

    pub fn readNoEof(self: *QuicStreamReader, buf: []u8) !void {
        var filled: usize = 0;
        while (filled < buf.len) {
            try self.io.drive();
            const n = quic.readStream(self.conn, self.sid, buf[filled..]) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => |e| return e,
            };
            if (n == 0) {
                if (quic.isStreamFinished(self.conn, self.sid)) return error.EndOfStream;
                continue;
            }
            filled += n;
        }
    }
};

/// Blocks until the peer opens a stream, polling both endpoints while waiting.
pub fn acceptIncomingStream(io: *const QuicIoPair, conn: *quic.QuicConnection) !quic.QuicStreamId {
    while (true) {
        try io.drive();
        const sid = quic.acceptStream(conn) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => |e| return e,
        };
        return sid;
    }
}

/// Sends FIN on `sid` (for example after `chunk_stream.writeChunkStream` on a client-opened uni stream).
pub fn finishStream(io: *const QuicIoPair, conn: *quic.QuicConnection, sid: quic.QuicStreamId) QuicStreamWriter.Error!void {
    while (true) {
        try io.drive();
        _ = quic.writeStream(conn, sid, &[_]u8{}, true) catch |err| switch (err) {
            error.FlowControlBlocked => continue,
            else => |e| return e,
        };
        return;
    }
}

fn maxIdleTimeoutMs(ns: u64) u32 {
    const ms = ns / std.time.ns_per_ms;
    return @intCast(@min(ms, @as(u64, std.math.maxInt(u32))));
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

test "QUIC wire: BCAST handshake, SESS open, CHUNK uni over stream adapters" {
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
        const p: u16 = @intCast(45150 + i);
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

    const c_conn = try quic.connect(client_ep, remote_s, "localhost");
    errdefer quic.destroy(client_ep, c_conn);

    var s_conn: ?*quic.QuicConnection = null;
    var rounds: u32 = 0;
    while (rounds < 30_000) : (rounds += 1) {
        try quic.poll(srv, 0);
        try quic.poll(client_ep, 0);
        if (s_conn == null) {
            s_conn = quic.tryAccept(srv);
        }
        if (quic.handshakeComplete(c_conn)) {
            if (s_conn) |sc| {
                if (quic.handshakeComplete(sc)) break;
            }
        }
    }

    const sc = s_conn orelse return error.MissingServerConnection;
    try std.testing.expect(quic.handshakeComplete(c_conn));
    try std.testing.expect(quic.handshakeComplete(sc));

    const pair_c = QuicIoPair{ .local = client_ep, .peer = srv };
    const pair_s = QuicIoPair{ .local = srv, .peer = client_ep };

    // BCAST: client opens bidi, server accepts and reads handshake.
    const b_sid = try quic.openStream(c_conn, true);
    {
        var w = QuicStreamWriter{ .io = &pair_c, .conn = c_conn, .sid = b_sid };
        try bcast_stream.writeBcastHandshakeOpen(&w, alloc, .{
            .version = 1,
            .channels = &.{ "blocks", "atts" },
            .peer_id = "peer-quic-wire",
        });
    }
    const b_in = try acceptIncomingStream(&pair_s, sc);
    var b_r = QuicStreamReader{ .io = &pair_s, .conn = sc, .sid = b_in };
    var b_msg = try bcast_stream.readBcastPeerHandshake(alloc, &b_r);
    defer b_msg.deinit(alloc);
    switch (b_msg) {
        .peer_handshake => |h| {
            try std.testing.expectEqual(@as(u32, 1), h.version);
            try std.testing.expectEqualStrings("peer-quic-wire", h.peer_id);
        },
        else => unreachable,
    }

    // SESS: client opens bidi, server reads selector + session_open.
    const s_sid = try quic.openStream(c_conn, true);
    {
        var w = QuicStreamWriter{ .io = &pair_c, .conn = c_conn, .sid = s_sid };
        try sess_stream.writeSessSessionOpen(&w, alloc, .{
            .channel = "ch1",
            .message_id = "mid-q",
            .preamble = &.{ 1, 2 },
            .initial_update = &.{ 3, 4 },
        });
    }
    const s_in = try acceptIncomingStream(&pair_s, sc);
    var s_r = QuicStreamReader{ .io = &pair_s, .conn = sc, .sid = s_in };
    const sel = try protocol.readSelectorByte(&s_r);
    try std.testing.expectEqual(protocol.Protocol.sess, sel);
    var sess_open = try sess_stream.readSessSessionOpenAfterSelector(alloc, &s_r);
    defer sess_open.deinit(alloc);
    switch (sess_open) {
        .session_open => |o| {
            try std.testing.expectEqualStrings("ch1", o.channel);
            try std.testing.expectEqualStrings("mid-q", o.message_id);
        },
        else => unreachable,
    }

    // CHUNK: client uni stream, framed payload, FIN.
    const u_sid = try quic.openUni(c_conn);
    {
        var w = QuicStreamWriter{ .io = &pair_c, .conn = c_conn, .sid = u_sid };
        try chunk_stream.writeChunkStream(&w, alloc, "c", "m", &.{9}, &.{ 0xAA, 0xBB });
    }
    try finishStream(&pair_c, c_conn, u_sid);

    const u_in = try acceptIncomingStream(&pair_s, sc);
    var u_r = QuicStreamReader{ .io = &pair_s, .conn = sc, .sid = u_in };
    var chunk_in = try chunk_stream.readChunkStream(alloc, &u_r);
    defer chunk_in.deinit(alloc);
    try std.testing.expectEqualStrings("c", chunk_in.header.channel);
    try std.testing.expectEqualStrings("m", chunk_in.header.message_id);
    try std.testing.expectEqualSlices(u8, &.{9}, chunk_in.header.chunk_id);
    try std.testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB }, chunk_in.payload);

    quic.destroy(srv, sc);
    quic.destroy(client_ep, c_conn);
}
