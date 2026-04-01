//! QUIC API compatible with the former `gitlab.com/devnw/zig/quic` usage in this repo.
//! Implemented with LiteSpeed lsquic + BoringSSL (see `vendor/lsquic_zig`).

const std = @import("std");
const posix = std.posix;

const lsquic = @cImport({
    @cInclude("lsquic.h");
    @cInclude("lsquic_types.h");
    @cInclude("lsquic_ethp2p_ext.h");
});

const ossl = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/x509.h");
});

var g_lsquic_global: bool = false;
var g_alpn_selected_buf: [128]u8 = undefined;

/// When true, first few `lsquic_engine_packet_in` calls print ret/len/role to stderr (see env below).
var g_trace_packet_in: bool = false;
var g_packet_in_trace_count: u32 = 0;

fn lsquicShimLogBuf(_: ?*anyopaque, buf: [*c]const u8, len: usize) callconv(.c) c_int {
    if (len == 0) return 0;
    _ = posix.write(posix.STDERR_FILENO, buf[0..len]) catch return -1;
    return 0;
}

const g_lsquic_stderr_logger_if: lsquic.lsquic_logger_if = .{
    .log_buf = lsquicShimLogBuf,
};

fn maybeInitLsquicStderrLogger() void {
    const want_log = posix.getenv("LSQUIC_LOG_LEVEL") != null or
        posix.getenv("LSQUIC_LOGGERLOPT") != null or blk: {
        const z = posix.getenv("ZIG_ETHP2P_LSQUIC_LOG") orelse break :blk false;
        break :blk z.len > 0 and !std.mem.eql(u8, z, "0");
    };
    if (!want_log) return;

    lsquic.lsquic_logger_init(&g_lsquic_stderr_logger_if, null, lsquic.LLTS_NONE);
    g_trace_packet_in = true;

    if (posix.getenv("LSQUIC_LOGGERLOPT")) |raw| {
        var stack: [512]u8 = undefined;
        if (raw.len >= stack.len) return;
        @memcpy(stack[0..raw.len], raw);
        stack[raw.len] = 0;
        _ = lsquic.lsquic_logger_lopt(@ptrCast(&stack));
        return;
    }

    const raw_level = posix.getenv("LSQUIC_LOG_LEVEL") orelse (posix.getenv("ZIG_ETHP2P_LSQUIC_LOG") orelse "debug");
    const use_level: []const u8 = if (std.mem.eql(u8, raw_level, "1")) "debug" else raw_level;
    var level_buf: [96]u8 = undefined;
    if (use_level.len >= level_buf.len) return;
    @memcpy(level_buf[0..use_level.len], use_level);
    level_buf[use_level.len] = 0;
    _ = lsquic.lsquic_set_log_level(@ptrCast(&level_buf));
}

fn ensureLsquicGlobal() void {
    if (g_lsquic_global) return;
    _ = lsquic.lsquic_global_init(lsquic.LSQUIC_GLOBAL_CLIENT | lsquic.LSQUIC_GLOBAL_SERVER);
    maybeInitLsquicStderrLogger();
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

        const pin_ret = lsquic.lsquic_engine_packet_in(
            self.engine,
            buf[0..@intCast(n)].ptr,
            @intCast(n),
            local_sa,
            @ptrCast(@alignCast(&peer.any)),
            self,
            0,
        );
        if (g_trace_packet_in) {
            const c = g_packet_in_trace_count;
            if (c < 32) {
                g_packet_in_trace_count = c + 1;
                std.debug.print("zig-ethp2p lsquic_engine_packet_in: ret={d} len={d} server={any}\n", .{
                    pin_ret,
                    n,
                    self.is_server,
                });
            }
        }
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
    pub const Stream = struct {
        raw: ?*lsquic.lsquic_stream_t,
        conn: *QuicConnection,
        read_buf: std.ArrayListUnmanaged(u8),
        write_buf: std.ArrayListUnmanaged(u8),
        write_off: usize,
        /// Set by `on_reset` when the peer resets this stream.
        /// `how`: 0 = read side reset (RESET_STREAM received),
        ///        1 = write side reset (STOP_SENDING received),
        ///        2 = both.
        reset_how: ?i32 = null,

        pub fn deinit(self: *Stream) void {
            const a = self.conn.ep.allocator.*;
            self.read_buf.deinit(a);
            self.write_buf.deinit(a);
        }
    };

    raw: *lsquic.lsquic_conn_t,
    ep: *QuicEndpoint,
    hsk_ok: bool,
    /// Incoming peer-initiated bidirectional streams waiting to be accepted.
    incoming_streams: std.ArrayListUnmanaged(*Stream),
    /// Incoming peer-initiated unidirectional streams waiting to be accepted.
    incoming_uni_streams: std.ArrayListUnmanaged(*Stream),
    streams_owned: std.ArrayListUnmanaged(*Stream),
    /// `streamMake` leaves a bidi `Stream` here until `on_new_stream` binds `raw`.
    stream_outgoing_ready: ?*Stream,
    /// `streamMakeUni` leaves a uni `Stream` here until `on_new_stream` binds `raw`.
    stream_outgoing_uni_ready: ?*Stream,

    fn freeAllStreams(self: *QuicConnection) void {
        const a = self.ep.allocator.*;
        if (self.stream_outgoing_ready) |p| {
            p.deinit();
            a.destroy(p);
            self.stream_outgoing_ready = null;
        }
        if (self.stream_outgoing_uni_ready) |p| {
            p.deinit();
            a.destroy(p);
            self.stream_outgoing_uni_ready = null;
        }
        self.incoming_streams.clearAndFree(a);
        self.incoming_uni_streams.clearAndFree(a);
        for (self.streams_owned.items) |st| {
            st.deinit();
            a.destroy(st);
        }
        self.streams_owned.clearAndFree(a);
    }

    fn removeStreamFromLists(self: *QuicConnection, st: *Stream) void {
        var i: usize = 0;
        while (i < self.streams_owned.items.len) {
            if (self.streams_owned.items[i] == st) {
                _ = self.streams_owned.swapRemove(i);
                break;
            }
            i += 1;
        }
        i = 0;
        while (i < self.incoming_streams.items.len) {
            if (self.incoming_streams.items[i] == st) {
                _ = self.incoming_streams.swapRemove(i);
                break;
            }
            i += 1;
        }
        i = 0;
        while (i < self.incoming_uni_streams.items.len) {
            if (self.incoming_uni_streams.items[i] == st) {
                _ = self.incoming_uni_streams.swapRemove(i);
                break;
            }
            i += 1;
        }
    }
};

pub const QuicStream = QuicConnection.Stream;

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

    // BoringSSL's default TLS 1.3 ClientHello omits Ed25519. A server certificate
    // signed with Ed25519 then fails with TLS alert 40 (handshake_failure).
    const verify_prefs = [_]u16{
        ossl.SSL_SIGN_ED25519,
        ossl.SSL_SIGN_ECDSA_SECP256R1_SHA256,
        ossl.SSL_SIGN_ECDSA_SECP384R1_SHA384,
        ossl.SSL_SIGN_ECDSA_SECP521R1_SHA512,
        ossl.SSL_SIGN_RSA_PKCS1_SHA256,
        ossl.SSL_SIGN_RSA_PKCS1_SHA384,
        ossl.SSL_SIGN_RSA_PKCS1_SHA512,
        ossl.SSL_SIGN_RSA_PSS_RSAE_SHA256,
        ossl.SSL_SIGN_RSA_PSS_RSAE_SHA384,
        ossl.SSL_SIGN_RSA_PSS_RSAE_SHA512,
    };
    if (ossl.SSL_CTX_set_verify_algorithm_prefs(ctx, &verify_prefs, verify_prefs.len) == 0)
        return error.TlsInit;

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
        .incoming_streams = .{},
        .incoming_uni_streams = .{},
        .streams_owned = .{},
        .stream_outgoing_ready = null,
        .stream_outgoing_uni_ready = null,
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
        q.freeAllStreams();
        lsquic.lsquic_conn_set_ctx(c.?, null);
        if (q.ep.connect_slot == q) q.ep.connect_slot = null;
        q.ep.allocator.destroy(q);
    }
}

fn onNewStream(stream_if_ctx: ?*anyopaque, s: ?*lsquic.lsquic_stream_t) callconv(.c) ?*lsquic.lsquic_stream_ctx_t {
    const ep: *QuicEndpoint = @ptrCast(@alignCast(stream_if_ctx.?));
    const alloc = ep.allocator.*;
    if (s == null) return null;

    const raw_conn = lsquic.lsquic_stream_conn(s.?);
    const qc: *QuicConnection = @ptrCast(@alignCast(lsquic.lsquic_conn_get_ctx(raw_conn) orelse return null));

    // QUIC stream ID encoding (RFC 9000 §2.1):
    //   bit 0: 0 = initiator is client, 1 = initiator is server
    //   bit 1: 0 = bidirectional, 1 = unidirectional
    const sid = lsquic.lsquic_stream_id(s.?);
    const is_uni = (sid & 0x2) != 0;

    if (is_uni) {
        // Unidirectional stream: check if it is our outgoing stream.
        if (qc.stream_outgoing_uni_ready) |tgt| {
            tgt.raw = s.?;
            lsquic.lsquic_stream_set_ctx(s.?, @ptrCast(tgt));
            qc.stream_outgoing_uni_ready = null;
            qc.streams_owned.append(alloc, tgt) catch {
                _ = lsquic.lsquic_stream_close(s.?);
                return null;
            };
            // Outgoing UNI streams are write-only; do not request reads.
            _ = lsquic.lsquic_stream_wantwrite(s.?, 0);
            return @ptrCast(tgt);
        }
        // Incoming UNI stream from peer.
        const inc = alloc.create(QuicStream) catch return null;
        inc.* = .{
            .raw = s.?,
            .conn = qc,
            .read_buf = .{},
            .write_buf = .{},
            .write_off = 0,
        };
        lsquic.lsquic_stream_set_ctx(s.?, @ptrCast(inc));
        qc.streams_owned.append(alloc, inc) catch {
            alloc.destroy(inc);
            return null;
        };
        qc.incoming_uni_streams.append(alloc, inc) catch {
            _ = qc.streams_owned.pop();
            alloc.destroy(inc);
            return null;
        };
        _ = lsquic.lsquic_stream_wantread(s.?, 1);
        return @ptrCast(inc);
    }

    // Bidirectional stream: check if it is our outgoing stream.
    if (qc.stream_outgoing_ready) |tgt| {
        tgt.raw = s.?;
        lsquic.lsquic_stream_set_ctx(s.?, @ptrCast(tgt));
        qc.stream_outgoing_ready = null;
        qc.streams_owned.append(alloc, tgt) catch {
            _ = lsquic.lsquic_stream_close(s.?);
            return null;
        };
        _ = lsquic.lsquic_stream_wantwrite(s.?, 0);
        _ = lsquic.lsquic_stream_wantread(s.?, 1);
        return @ptrCast(tgt);
    }

    // Incoming bidirectional stream from peer.
    const inc = alloc.create(QuicStream) catch return null;
    inc.* = .{
        .raw = s.?,
        .conn = qc,
        .read_buf = .{},
        .write_buf = .{},
        .write_off = 0,
    };
    lsquic.lsquic_stream_set_ctx(s.?, @ptrCast(inc));
    qc.streams_owned.append(alloc, inc) catch {
        alloc.destroy(inc);
        return null;
    };
    qc.incoming_streams.append(alloc, inc) catch {
        _ = qc.streams_owned.pop();
        alloc.destroy(inc);
        return null;
    };
    _ = lsquic.lsquic_stream_wantread(s.?, 1);
    return @ptrCast(inc);
}

fn onStreamRead(s: ?*lsquic.lsquic_stream_t, h: ?*lsquic.lsquic_stream_ctx_t) callconv(.c) void {
    const st: *QuicStream = @ptrCast(@alignCast(h.?));
    var chunk: [16 * 1024]u8 = undefined;
    while (true) {
        const n = lsquic.lsquic_stream_read(s.?, @ptrCast(&chunk), chunk.len);
        if (n == 0) {
            _ = lsquic.lsquic_stream_wantread(s.?, 0);
            return;
        }
        if (n < 0) {
            const e = posix.errno(@as(isize, n));
            if (e == .AGAIN) {
                _ = lsquic.lsquic_stream_wantread(s.?, 1);
                return;
            }
            _ = lsquic.lsquic_stream_wantread(s.?, 0);
            return;
        }
        const got: usize = @intCast(n);
        st.read_buf.appendSlice(st.conn.ep.allocator.*, chunk[0..got]) catch {
            _ = lsquic.lsquic_stream_wantread(s.?, 0);
            return;
        };
    }
}

fn onStreamWrite(s: ?*lsquic.lsquic_stream_t, h: ?*lsquic.lsquic_stream_ctx_t) callconv(.c) void {
    const st: *QuicStream = @ptrCast(@alignCast(h.?));
    while (st.write_off < st.write_buf.items.len) {
        const rest = st.write_buf.items[st.write_off..];
        const n = lsquic.lsquic_stream_write(s.?, rest.ptr, rest.len);
        if (n < 0) return;
        if (n == 0) {
            _ = lsquic.lsquic_stream_wantwrite(s.?, 1);
            return;
        }
        st.write_off += @intCast(n);
    }
    st.write_buf.clearRetainingCapacity();
    st.write_off = 0;
    _ = lsquic.lsquic_stream_flush(s.?);
    _ = lsquic.lsquic_stream_wantwrite(s.?, 0);
}

fn onStreamClose(s: ?*lsquic.lsquic_stream_t, h: ?*lsquic.lsquic_stream_ctx_t) callconv(.c) void {
    _ = s;
    if (h == null) return;
    const st: *QuicStream = @ptrCast(@alignCast(h.?));
    st.raw = null;
    st.conn.removeStreamFromLists(st);
    st.deinit();
    st.conn.ep.allocator.destroy(st);
}

fn onStreamReset(s: ?*lsquic.lsquic_stream_t, h: ?*lsquic.lsquic_stream_ctx_t, how: c_int) callconv(.c) void {
    _ = s;
    if (h == null) return;
    const st: *QuicStream = @ptrCast(@alignCast(h.?));
    // Record which direction was reset: 0=read, 1=write, 2=both.
    st.reset_how = how;
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
    .on_reset = onStreamReset,
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
    // Avoid AL_IDLE "lack of progress" while a connection is still completing setup
    // (common when the app drives the engine in a tight loop).
    settings.es_noprogress_timeout = 0;
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
    // `timeout_ms == 0` is used in tight loops; without a wall-clock nudge, lsquic's
    // advisory timers (PTO, etc.) may never elapse. Use the engine hint when present,
    // otherwise sleep briefly so multi-engine handshakes still make progress.
    if (timeout_ms == 0) {
        var diff_us: c_int = 0;
        const has_tick = lsquic.lsquic_engine_earliest_adv_tick(ep.engine, &diff_us) != 0;
        // Cap per call so tight loops (e.g. tests) do not sleep tens of ms per poll;
        // many iterations still accumulate enough wall time for PTO-sized delays.
        var sleep_us: u64 = 50;
        if (has_tick and diff_us > 0) {
            sleep_us = @min(@as(u64, @intCast(diff_us)), 500);
        }
        std.Thread.sleep(sleep_us * std.time.ns_per_us);
    }
}

pub fn tryAccept(ep: *QuicEndpoint) ?*QuicConnection {
    if (ep.accept_queue.items.len == 0) return null;
    return ep.accept_queue.swapRemove(0);
}

fn connHandshakeReady(conn: *const QuicConnection) bool {
    if (conn.hsk_ok) return true;
    // lsquic sometimes completes the TLS+QUIC handshake without invoking `on_hsk_done`
    // with `LSQ_HSK_OK` on the server side; `lsquic_conn_status` reflects readiness.
    var errscratch: [1]u8 = undefined;
    const st = lsquic.lsquic_conn_status(conn.raw, @ptrCast(&errscratch), errscratch.len);
    return st == @as(lsquic.enum_LSQUIC_CONN_STATUS, @intCast(lsquic.LSCONN_ST_CONNECTED));
}

pub fn handshakeComplete(conn: *const QuicConnection) bool {
    return connHandshakeReady(conn);
}

pub fn getNegotiatedAlpn(conn: *const QuicConnection) ?[]const u8 {
    if (!connHandshakeReady(conn)) return null;
    return conn.ep.first_alpn;
}

/// Pop the next peer-initiated bidirectional stream, if any. Does not remove the stream from
/// ownership tracking; it is still freed when the stream closes or the connection is destroyed.
pub fn tryAcceptIncomingStream(conn: *QuicConnection) ?*QuicStream {
    if (conn.incoming_streams.items.len == 0) return null;
    return conn.incoming_streams.swapRemove(0);
}

/// Pop the next peer-initiated unidirectional stream, if any.
/// These are the streams used by the ethp2p reference for BCAST, SESS, and CHUNK.
pub fn tryAcceptIncomingUniStream(conn: *QuicConnection) ?*QuicStream {
    if (conn.incoming_uni_streams.items.len == 0) return null;
    return conn.incoming_uni_streams.swapRemove(0);
}

/// Open a locally initiated bidirectional stream (calls `lsquic_conn_make_stream`). Requires a
/// completed handshake. Drives `poll` on this connection until the stream exists or a bound is hit.
/// When `poll_peer` is non-null, it is polled each iteration as well (needed on loopback so both
/// engines process packets while the stream is being created).
pub fn streamMake(conn: *QuicConnection, poll_peer: ?*QuicEndpoint) !*QuicStream {
    if (conn.stream_outgoing_ready != null) return error.StreamSpawnPending;
    if (!connHandshakeReady(conn)) return error.HandshakeNotComplete;
    const alloc = conn.ep.allocator.*;
    const qs = try alloc.create(QuicStream);
    qs.* = .{
        .raw = null,
        .conn = conn,
        .read_buf = .{},
        .write_buf = .{},
        .write_off = 0,
    };
    conn.stream_outgoing_ready = qs;
    lsquic.lsquic_conn_make_stream(conn.raw);
    conn.ep.processEngine();
    var i: u32 = 0;
    while (qs.raw == null and i < 10_000) : (i += 1) {
        try poll(conn.ep, 0);
        if (poll_peer) |p| try poll(p, 0);
    }
    if (qs.raw == null) {
        if (conn.stream_outgoing_ready == qs) conn.stream_outgoing_ready = null;
        qs.deinit();
        alloc.destroy(qs);
        return error.StreamCreateFailed;
    }
    return qs;
}

/// Open a locally initiated unidirectional stream (calls `lsquic_conn_make_uni_stream`). Requires
/// a completed handshake. The ethp2p reference uses UNI streams for BCAST control, SESS session
/// open/routing, and CHUNK data (`peer.go`, `peer_ctrl.go`, `peer_in.go`).
///
/// `on_new_stream` fires synchronously inside `lsquic_conn_make_uni_stream`; the polling loop is a
/// safety fallback in case lsquic defers the callback in some edge case.
pub fn streamMakeUni(conn: *QuicConnection, poll_peer: ?*QuicEndpoint) !*QuicStream {
    if (conn.stream_outgoing_uni_ready != null) return error.StreamSpawnPending;
    if (!connHandshakeReady(conn)) return error.HandshakeNotComplete;
    const alloc = conn.ep.allocator.*;
    const qs = try alloc.create(QuicStream);
    qs.* = .{
        .raw = null,
        .conn = conn,
        .read_buf = .{},
        .write_buf = .{},
        .write_off = 0,
    };
    conn.stream_outgoing_uni_ready = qs;
    _ = lsquic.lsquic_conn_make_uni_stream(conn.raw);
    // on_new_stream fires synchronously; qs.raw should be set already.
    if (qs.raw == null) {
        conn.ep.processEngine();
        var i: u32 = 0;
        while (qs.raw == null and i < 10_000) : (i += 1) {
            try poll(conn.ep, 0);
            if (poll_peer) |p| try poll(p, 0);
        }
    }
    if (qs.raw == null) {
        if (conn.stream_outgoing_uni_ready == qs) conn.stream_outgoing_uni_ready = null;
        qs.deinit();
        alloc.destroy(qs);
        return error.StreamCreateFailed;
    }
    return qs;
}

/// Cancel the write side of a stream, sending a QUIC RESET_STREAM frame to the peer.
/// This is used by the ethp2p reference when a session is reconstructed (`sessCodeReconstructed`).
/// Note: the lsquic 4.3 public API does not expose an application error code for this frame;
/// `lsquic_stream_shutdown(SHUT_WR)` sends a FIN rather than RESET_STREAM. Use `lsquic_stream_close`
/// as the closest available equivalent.
pub fn streamCancelWrite(st: *QuicStream) void {
    if (st.raw) |s| _ = lsquic.lsquic_stream_close(s);
}

/// Cancel the read side of a stream, sending a QUIC STOP_SENDING frame to the peer.
pub fn streamCancelRead(st: *QuicStream) void {
    if (st.raw) |s| _ = lsquic.lsquic_stream_shutdown(s, 0); // SHUT_RD
}

pub fn streamQueueWrite(st: *QuicStream, data: []const u8) !void {
    const s = st.raw orelse return error.StreamClosed;
    try st.write_buf.appendSlice(st.conn.ep.allocator.*, data);
    _ = lsquic.lsquic_stream_wantwrite(s, 1);
}

/// Poll both endpoints until the queued write buffer is drained or `max_rounds` is exhausted.
pub fn streamDrainWrites(st: *QuicStream, peer: *QuicEndpoint, max_rounds: u32) !void {
    var r: u32 = 0;
    while (st.write_buf.items.len > 0 and r < max_rounds) : (r += 1) {
        try poll(st.conn.ep, 0);
        try poll(peer, 0);
    }
    if (st.write_buf.items.len > 0) return error.StreamWriteTimeout;
}

/// Send-side FIN for the stream (QUIC half-close), analogous to `shutdown(SHUT_WR)`.
pub fn streamShutdownWrite(st: *QuicStream) void {
    if (st.raw) |s| {
        _ = lsquic.lsquic_stream_shutdown(s, @intCast(@intFromEnum(posix.SHUT.WR)));
    }
}

pub fn streamReadSlice(st: *const QuicStream) []const u8 {
    return st.read_buf.items;
}

/// Drop the first `n` bytes from the stream read buffer (after successfully decoding them).
pub fn streamConsumeReadPrefix(st: *QuicStream, n: usize) !void {
    if (n > st.read_buf.items.len) return error.StreamReadUnderflow;
    try st.read_buf.replaceRange(st.conn.ep.allocator.*, 0, n, &.{});
}
