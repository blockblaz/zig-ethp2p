//! QUIC API compatible with the former `gitlab.com/devnw/zig/quic` usage in this repo.
//! Implemented with LiteSpeed lsquic + BoringSSL (see `vendor/lsquic_zig`).

const std = @import("std");
const posix = std.posix;

const lsquic = @cImport({
    @cInclude("lsquic.h");
    @cInclude("lsquic_types.h");
});

const ossl = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/x509.h");
});

var g_lsquic_global: bool = false;
var g_alpn_selected_buf: [128]u8 = undefined;

fn ensureLsquicGlobal() void {
    if (g_lsquic_global) return;
    _ = lsquic.lsquic_global_init(lsquic.LSQUIC_GLOBAL_CLIENT | lsquic.LSQUIC_GLOBAL_SERVER);
    g_lsquic_global = true;
}

pub const QuicConfig = struct {
    alpn: *const [1][]const u8,
    inline_server_cert_der: ?[]const u8 = null,
    inline_server_priv_p256: ?[]const u8 = null,
    allow_insecure: bool = false,
    max_idle_timeout_ms: u32 = 30_000,
    max_udp_payload: u32 = 1350,
};

pub const QuicEndpoint = struct {
    sock: posix.socket_t,
    engine: *lsquic.lsquic_engine_t,
    ssl_ctx: *ossl.SSL_CTX,
    allocator: *std.mem.Allocator,
    is_server: bool,
    local_addr: std.net.Address,
    resolved_local: ?std.net.Address,
    accept_queue: std.ArrayListUnmanaged(*QuicConnection),
    connect_slot: ?*QuicConnection,
    first_alpn: []const u8,
    alpn_wire: []u8,
    alpn_cstr: [:0]u8,
    base_plpmtu: u16,
    sni_z: ?[:0]u8 = null,
    settings: lsquic.lsquic_engine_settings,
    api: lsquic.lsquic_engine_api,

    fn isWildcardLocal(addr: std.net.Address) bool {
        return switch (addr.any.family) {
            posix.AF.INET => {
                const b: *const [4]u8 = @ptrCast(&addr.in.sa.addr);
                return std.mem.allEqual(u8, b, 0);
            },
            posix.AF.INET6 => {
                const b: *const [16]u8 = @ptrCast(&addr.in6.sa.addr);
                return std.mem.allEqual(u8, b, 0);
            },
            else => false,
        };
    }

    fn resolveLocalForWildcard(local: std.net.Address, remote: std.net.Address) std.net.Address {
        if (!isWildcardLocal(local)) return local;
        const sock = posix.socket(remote.any.family, posix.SOCK.DGRAM, posix.IPPROTO.UDP) catch return local;
        defer posix.close(sock);
        posix.connect(sock, &remote.any, remote.getOsSockLen()) catch return local;
        var resolved: std.net.Address = undefined;
        var len: posix.socklen_t = @sizeOf(std.net.Address);
        posix.getsockname(sock, &resolved.any, &len) catch return local;
        resolved.setPort(local.getPort());
        return resolved;
    }

    fn processEngine(self: *QuicEndpoint) void {
        // Drive lsquic state. Long unbounded sleeps on `earliest_adv_tick` can exceed
        // `es_idle_timeout` (~1s when max idle ms is 0) and close the connection mid-call.
        // Allow only a small wall-clock budget per invocation so PTO-style timers can advance.
        var slept_ns: u64 = 0;
        const max_sleep_ns: u64 = 4 * std.time.ns_per_ms;
        var guard: u32 = 0;
        var zero_tick_streak: u32 = 0;
        while (guard < 4096) : (guard += 1) {
            lsquic.lsquic_engine_process_conns(self.engine);
            while (lsquic.lsquic_engine_has_unsent_packets(self.engine) != 0) {
                lsquic.lsquic_engine_send_unsent_packets(self.engine);
            }
            var diff_us: c_int = 0;
            if (lsquic.lsquic_engine_earliest_adv_tick(self.engine, &diff_us) == 0) {
                zero_tick_streak += 1;
                if (zero_tick_streak >= 64) break;
                continue;
            }
            zero_tick_streak = 0;
            if (diff_us > 0 and slept_ns < max_sleep_ns) {
                const us_ask: u64 = @intCast(@max(diff_us, 1));
                const us_cap: u64 = @min(us_ask, 500);
                const ns_try = us_cap * std.time.ns_per_us;
                const ns = @min(ns_try, max_sleep_ns - slept_ns);
                std.Thread.sleep(ns);
                slept_ns += ns;
            }
        }
    }

    /// Reads one datagram if available. Returns `false` when the socket has no more buffered data.
    fn recvOneIfAvailable(self: *QuicEndpoint) !bool {
        var buf: [65536]u8 = undefined;
        var peer: std.net.Address = undefined;
        var peer_len: posix.socklen_t = @sizeOf(std.net.Address);
        const n = posix.recvfrom(self.sock, &buf, 0, &peer.any, &peer_len) catch |err| switch (err) {
            error.WouldBlock => return false,
            else => |e| return e,
        };
        if (n == 0) return false;

        if (!self.is_server) {
            var la_len: posix.socklen_t = @sizeOf(std.net.Address);
            posix.getsockname(self.sock, &self.local_addr.any, &la_len) catch {};
        }

        const local_sa: ?*const lsquic.struct_sockaddr = blk: {
            if (self.is_server and isWildcardLocal(self.local_addr)) {
                if (self.resolved_local == null) {
                    self.resolved_local = resolveLocalForWildcard(self.local_addr, peer);
                }
                if (self.resolved_local) |*r| break :blk @ptrCast(@alignCast(&r.any));
            }
            break :blk @ptrCast(@alignCast(&self.local_addr.any));
        };

        _ = lsquic.lsquic_engine_packet_in(
            self.engine,
            buf[0..@intCast(n)].ptr,
            @intCast(n),
            local_sa,
            @ptrCast(@alignCast(&peer.any)),
            self,
            0,
        );
        self.processEngine();
        return true;
    }

    fn waitReadable(self: *QuicEndpoint, timeout_ms: u32) !bool {
        if (timeout_ms == 0) return true;
        var pfd = [_]posix.pollfd{.{
            .fd = self.sock,
            .events = posix.POLL.IN,
            .revents = 0,
        }};
        const n = try posix.poll(&pfd, @intCast(timeout_ms));
        return n > 0 and (pfd[0].revents & posix.POLL.IN) != 0;
    }
};

pub const QuicConnection = struct {
    raw: *lsquic.lsquic_conn_t,
    ep: *QuicEndpoint,
    hsk_ok: bool,
};

fn buildAlpnProtos(proto: []const u8, out: []u8) !usize {
    if (proto.len > 255 or out.len < 1 + proto.len) return error.AlpnTooLong;
    out[0] = @intCast(proto.len);
    @memcpy(out[1 .. 1 + proto.len], proto);
    return 1 + proto.len;
}

fn alpnSelectCb(
    ssl: ?*ossl.SSL,
    out_arg: [*c][*c]const u8,
    out_len_arg: [*c]u8,
    inp: [*c]const u8,
    in_len: c_uint,
    arg: ?*anyopaque,
) callconv(.c) c_int {
    _ = ssl;
    _ = arg;
    const out: *[*c]const u8 = @ptrCast(@alignCast(out_arg));
    const out_len: *u8 = @ptrCast(out_len_arg);
    const want = "eth-ec-broadcast";
    var i: usize = 0;
    const inlen_us: usize = @intCast(in_len);
    while (i < inlen_us) {
        const len: usize = @intCast(inp[i]);
        i += 1;
        if (i + len > inlen_us) return ossl.SSL_TLSEXT_ERR_ALERT_FATAL;
        const offered: []const u8 = inp[i .. i + len];
        i += len;
        if (std.mem.eql(u8, offered, want)) {
            if (len > g_alpn_selected_buf.len) return ossl.SSL_TLSEXT_ERR_ALERT_FATAL;
            @memcpy(g_alpn_selected_buf[0..len], offered);
            out.* = @ptrCast(g_alpn_selected_buf[0..len].ptr);
            out_len.* = @intCast(len);
            return ossl.SSL_TLSEXT_ERR_OK;
        }
    }
    return ossl.SSL_TLSEXT_ERR_ALERT_FATAL;
}

fn makeSslCtxServer(cert_der: []const u8, key_der: []const u8) !*ossl.SSL_CTX {
    const ctx = ossl.SSL_CTX_new(ossl.TLS_method()) orelse return error.TlsInit;
    errdefer ossl.SSL_CTX_free(ctx);

    if (ossl.SSL_CTX_set_min_proto_version(ctx, ossl.TLS1_3_VERSION) == 0) return error.TlsInit;
    if (ossl.SSL_CTX_set_max_proto_version(ctx, ossl.TLS1_3_VERSION) == 0) return error.TlsInit;
    _ = ossl.SSL_CTX_set_default_verify_paths(ctx);

    var cert_p: [*c]const u8 = @ptrCast(cert_der.ptr);
    const x509 = ossl.d2i_X509(null, &cert_p, @intCast(cert_der.len)) orelse return error.TlsInit;
    defer ossl.X509_free(x509);
    if (ossl.SSL_CTX_use_certificate(ctx, x509) == 0) return error.TlsInit;

    var key_p: [*c]const u8 = @ptrCast(key_der.ptr);
    const pkey = ossl.d2i_AutoPrivateKey(null, &key_p, @intCast(key_der.len)) orelse return error.TlsInit;
    defer ossl.EVP_PKEY_free(pkey);
    if (ossl.SSL_CTX_use_PrivateKey(ctx, pkey) == 0) return error.TlsInit;
    if (ossl.SSL_CTX_check_private_key(ctx) == 0) return error.TlsInit;

    // QUIC server ALPN is chosen in `ssl_negotiate_alpn` via this callback only; do not use
    // `SSL_CTX_set_alpn_protos` here — in BoringSSL that field is the *client* ALPN wire list.
    _ = ossl.SSL_CTX_set_alpn_select_cb(ctx, alpnSelectCb, null);
    _ = ossl.SSL_CTX_set_verify(ctx, ossl.SSL_VERIFY_NONE, null);

    return ctx;
}

fn makeSslCtxClient(allow_insecure: bool, alpn_wire: []const u8) !*ossl.SSL_CTX {
    const ctx = ossl.SSL_CTX_new(ossl.TLS_method()) orelse return error.TlsInit;
    errdefer ossl.SSL_CTX_free(ctx);

    if (ossl.SSL_CTX_set_min_proto_version(ctx, ossl.TLS1_3_VERSION) == 0) return error.TlsInit;
    if (ossl.SSL_CTX_set_max_proto_version(ctx, ossl.TLS1_3_VERSION) == 0) return error.TlsInit;
    _ = ossl.SSL_CTX_set_default_verify_paths(ctx);

    if (ossl.SSL_CTX_set_alpn_protos(ctx, alpn_wire.ptr, @intCast(alpn_wire.len)) != 0) return error.TlsInit;

    if (allow_insecure) {
        _ = ossl.SSL_CTX_set_verify(ctx, ossl.SSL_VERIFY_NONE, null);
    } else {
        _ = ossl.SSL_CTX_set_verify(ctx, ossl.SSL_VERIFY_PEER, null);
    }

    return ctx;
}

fn getSslCtx(peer_ctx: ?*anyopaque, _: ?*const lsquic.struct_sockaddr) callconv(.c) ?*lsquic.struct_ssl_ctx_st {
    const ep: *QuicEndpoint = @ptrCast(@alignCast(peer_ctx.?));
    return @ptrCast(ep.ssl_ctx);
}

fn packetsOut(ctx: ?*anyopaque, specs: ?[*]const lsquic.lsquic_out_spec, n_specs: u32) callconv(.c) c_int {
    const ep: *QuicEndpoint = @ptrCast(@alignCast(ctx.?));
    var sent: u32 = 0;
    for (specs.?[0..n_specs]) |spec| {
        var msg: posix.msghdr_const = std.mem.zeroes(posix.msghdr_const);
        const dest_sa: ?*const posix.sockaddr = @ptrCast(@alignCast(spec.dest_sa));
        if (dest_sa == null) return if (sent == 0) -1 else @intCast(sent);
        msg.name = dest_sa;
        msg.namelen = switch (dest_sa.?.family) {
            posix.AF.INET => @sizeOf(posix.sockaddr.in),
            posix.AF.INET6 => @sizeOf(posix.sockaddr.in6),
            else => return if (sent == 0) -1 else @intCast(sent),
        };
        msg.iov = @ptrCast(spec.iov.?);
        msg.iovlen = @intCast(spec.iovlen);

        // lsquic inspects `errno` after this callback; Zig's `posix.sendmsg` error path can leave it stale.
        const rc = posix.system.sendmsg(ep.sock, &msg, 0);
        if (rc < 0) {
            if (sent > 0) return @intCast(sent);
            return -1;
        }
        sent += 1;
    }
    return @intCast(sent);
}

fn onNewConn(stream_if_ctx: ?*anyopaque, c: ?*lsquic.lsquic_conn_t) callconv(.c) ?*lsquic.lsquic_conn_ctx_t {
    const ep: *QuicEndpoint = @ptrCast(@alignCast(stream_if_ctx.?));
    const qc = ep.allocator.create(QuicConnection) catch return null;
    qc.* = .{
        .raw = c.?,
        .ep = ep,
        .hsk_ok = false,
    };
    lsquic.lsquic_conn_set_ctx(c, @ptrCast(qc));
    if (ep.is_server) {
        ep.accept_queue.append(ep.allocator.*, qc) catch {
            ep.allocator.destroy(qc);
            return null;
        };
    } else {
        ep.connect_slot = qc;
    }
    return @ptrCast(qc);
}

fn onConnClosed(c: ?*lsquic.lsquic_conn_t) callconv(.c) void {
    const qc: ?*QuicConnection = @ptrCast(@alignCast(lsquic.lsquic_conn_get_ctx(c.?)));
    if (qc) |q| {
        lsquic.lsquic_conn_set_ctx(c.?, null);
        if (q.ep.connect_slot == q) q.ep.connect_slot = null;
        q.ep.allocator.destroy(q);
    }
}

fn onNewStream(stream_if_ctx: ?*anyopaque, s: ?*lsquic.lsquic_stream_t) callconv(.c) ?*lsquic.lsquic_stream_ctx_t {
    _ = stream_if_ctx;
    _ = s;
    return null;
}

fn onStreamRead(s: ?*lsquic.lsquic_stream_t, h: ?*lsquic.lsquic_stream_ctx_t) callconv(.c) void {
    _ = s;
    _ = h;
}

fn onStreamWrite(s: ?*lsquic.lsquic_stream_t, h: ?*lsquic.lsquic_stream_ctx_t) callconv(.c) void {
    _ = s;
    _ = h;
}

fn onStreamClose(s: ?*lsquic.lsquic_stream_t, h: ?*lsquic.lsquic_stream_ctx_t) callconv(.c) void {
    _ = s;
    _ = h;
}

fn onHskDone(c: ?*lsquic.lsquic_conn_t, status: lsquic.enum_lsquic_hsk_status) callconv(.c) void {
    if (status != lsquic.LSQ_HSK_OK and status != lsquic.LSQ_HSK_RESUMED_OK) return;
    const qc: *QuicConnection = @ptrCast(@alignCast(lsquic.lsquic_conn_get_ctx(c.?)));
    qc.hsk_ok = true;
}

const stream_if: lsquic.lsquic_stream_if = .{
    .on_new_conn = onNewConn,
    .on_goaway_received = null,
    .on_conn_closed = onConnClosed,
    .on_new_stream = onNewStream,
    .on_read = onStreamRead,
    .on_write = onStreamWrite,
    .on_close = onStreamClose,
    .on_dg_write = null,
    .on_datagram = null,
    .on_hsk_done = onHskDone,
    .on_new_token = null,
    .on_sess_resume_info = null,
    .on_reset = null,
    .on_conncloseframe_received = null,
};

fn parseBindAddr(s: []const u8) !std.net.Address {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.BadAddress;
    const host = s[0..colon];
    const port = try std.fmt.parseInt(u16, s[colon + 1 ..], 10);
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') {
        return try std.net.Address.parseIp(host[1 .. host.len - 1], port);
    }
    return try std.net.Address.parseIp(host, port);
}

pub fn endpointInit(allocator: *std.mem.Allocator, bind_s: []const u8, qc: *QuicConfig) !*QuicEndpoint {
    ensureLsquicGlobal();

    const addr = try parseBindAddr(bind_s);
    const is_server = qc.inline_server_cert_der != null;

    const sock = try posix.socket(addr.any.family, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, posix.IPPROTO.UDP);
    errdefer posix.close(sock);
    const reuse: c_int = 1;
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuse));
    try posix.bind(sock, &addr.any, addr.getOsSockLen());

    var local_addr: std.net.Address = undefined;
    var la_len: posix.socklen_t = @sizeOf(std.net.Address);
    try posix.getsockname(sock, &local_addr.any, &la_len);

    const first_alpn = qc.alpn.*[0];
    const alpn_wire = try allocator.alloc(u8, 1 + first_alpn.len);
    errdefer allocator.free(alpn_wire);
    const wlen = try buildAlpnProtos(first_alpn, alpn_wire);
    if (wlen != alpn_wire.len) return error.AlpnTooLong;

    const alpn_cstr = try allocator.allocSentinel(u8, first_alpn.len, 0);
    errdefer allocator.free(alpn_cstr);
    @memcpy(alpn_cstr[0..first_alpn.len], first_alpn);

    const ssl_ctx: *ossl.SSL_CTX = if (is_server) blk: {
        const cert = qc.inline_server_cert_der orelse return error.TlsInit;
        const key = qc.inline_server_priv_p256 orelse return error.TlsInit;
        break :blk try makeSslCtxServer(cert, key);
    } else try makeSslCtxClient(qc.allow_insecure, alpn_wire);
    errdefer ossl.SSL_CTX_free(ssl_ctx);

    var flags_eng: c_uint = 0;
    if (is_server) flags_eng |= lsquic.LSENG_SERVER;

    var settings: lsquic.lsquic_engine_settings = undefined;
    lsquic.lsquic_engine_init_settings(&settings, flags_eng);
    settings.es_versions = lsquic.LSQUIC_IETF_VERSIONS;
    if (is_server) {
        // Default server `es_support_srej` issues Retry on tokenless Initials; that path
        // can strand the handshake for loopback tests that expect a single mini→full flow.
        settings.es_support_srej = 0;
    }
    const idle_s: u32 = @intCast(@max(1, qc.max_idle_timeout_ms / std.time.ms_per_s));
    settings.es_idle_timeout = @min(idle_s, 600);
    settings.es_base_plpmtu = @truncate(qc.max_udp_payload);

    var err_buf: [256]u8 = undefined;
    if (lsquic.lsquic_engine_check_settings(&settings, flags_eng, &err_buf, err_buf.len) != 0) {
        return error.TlsInit;
    }

    var api = std.mem.zeroes(lsquic.lsquic_engine_api);
    api.ea_settings = &settings;
    api.ea_stream_if = &stream_if;
    api.ea_stream_if_ctx = undefined;
    api.ea_packets_out = packetsOut;
    api.ea_packets_out_ctx = undefined;
    api.ea_get_ssl_ctx = getSslCtx;
    // Non-HTTP engines: lsquic stores this as `enp_alpn` (length-prefixed wire) for
    // `esi_alpn` / application-secret ALPN verification on both client and server.
    api.ea_alpn = alpn_cstr.ptr;

    const ep = try allocator.create(QuicEndpoint);
    errdefer allocator.destroy(ep);
    ep.* = .{
        .sock = sock,
        .engine = undefined,
        .ssl_ctx = ssl_ctx,
        .allocator = allocator,
        .is_server = is_server,
        .local_addr = local_addr,
        .resolved_local = null,
        .accept_queue = .{},
        .connect_slot = null,
        .first_alpn = first_alpn,
        .alpn_wire = alpn_wire,
        .alpn_cstr = alpn_cstr,
        .base_plpmtu = @truncate(qc.max_udp_payload),
        .sni_z = null,
        .settings = settings,
        .api = undefined,
    };
    api.ea_stream_if_ctx = ep;
    api.ea_packets_out_ctx = ep;
    ep.api = api;

    const eng = lsquic.lsquic_engine_new(flags_eng, &ep.api) orelse return error.TlsInit;
    ep.engine = eng;

    return ep;
}

pub fn endpointDeinit(ep: *QuicEndpoint) void {
    while (ep.accept_queue.items.len > 0) {
        const c = ep.accept_queue.swapRemove(ep.accept_queue.items.len - 1);
        lsquic.lsquic_conn_close(c.raw);
    }
    ep.accept_queue.deinit(ep.allocator.*);
    if (ep.connect_slot) |q| {
        lsquic.lsquic_conn_close(q.raw);
        ep.processEngine();
    }
    lsquic.lsquic_engine_destroy(ep.engine);
    posix.close(ep.sock);
    ossl.SSL_CTX_free(ep.ssl_ctx);
    if (ep.sni_z) |s| ep.allocator.free(s);
    ep.allocator.free(ep.alpn_wire);
    ep.allocator.free(ep.alpn_cstr);
    ep.allocator.destroy(ep);
}

pub fn connect(ep: *QuicEndpoint, remote_s: []const u8, hostname: []const u8) !*QuicConnection {
    ep.connect_slot = null;
    const remote = try parseBindAddr(remote_s);
    if (ep.sni_z) |old| ep.allocator.free(old);
    const hz = try ep.allocator.allocSentinel(u8, hostname.len, 0);
    @memcpy(hz[0..hostname.len], hostname);
    ep.sni_z = hz;

    const local_sa: ?*const lsquic.struct_sockaddr = @ptrCast(@alignCast(&ep.local_addr.any));
    const remote_sa: ?*const lsquic.struct_sockaddr = @ptrCast(@alignCast(&remote.any));

    const raw_conn = lsquic.lsquic_engine_connect(
        ep.engine,
        lsquic.N_LSQVER,
        local_sa,
        remote_sa,
        ep,
        null,
        hz.ptr,
        ep.base_plpmtu,
        null,
        0,
        null,
        0,
    ) orelse return error.ConnectFailed;

    const ctx_after = lsquic.lsquic_conn_get_ctx(raw_conn);
    const qc: *QuicConnection = if (ep.connect_slot) |s|
        s
    else
        @ptrCast(@alignCast(ctx_after orelse return error.ConnectFailed));

    ep.processEngine();

    if (lsquic.lsquic_conn_get_ctx(raw_conn) == null) return error.ConnectFailed;
    return qc;
}

pub fn destroy(ep: *QuicEndpoint, conn: *QuicConnection) void {
    lsquic.lsquic_conn_close(conn.raw);
    ep.processEngine();
}

pub fn poll(ep: *QuicEndpoint, timeout_ms: u32) !void {
    if (try ep.waitReadable(timeout_ms)) {
        while (try ep.recvOneIfAvailable()) {}
    }
    ep.processEngine();
}

pub fn tryAccept(ep: *QuicEndpoint) ?*QuicConnection {
    if (ep.accept_queue.items.len == 0) return null;
    return ep.accept_queue.swapRemove(0);
}

pub fn handshakeComplete(conn: *const QuicConnection) bool {
    return conn.hsk_ok;
}

pub fn getNegotiatedAlpn(conn: *const QuicConnection) ?[]const u8 {
    if (!conn.hsk_ok) return null;
    return conn.ep.first_alpn;
}
