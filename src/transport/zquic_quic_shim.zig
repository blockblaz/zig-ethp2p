//! QUIC API compatible with the former `gitlab.com/devnw/zig/quic` usage in this repo.
//! Implemented with pure-Zig [zquic](https://github.com/ch4r10t33r/zquic) (TLS 1.3 + QUIC).

const std = @import("std");
const posix = std.posix;

const zquic = @import("zquic");
const io = zquic.transport.io;

pub const QuicConfig = struct {
    alpn: *const [1][]const u8,
    inline_server_cert_der: ?[]const u8 = null,
    inline_server_priv_p256: ?[]const u8 = null,
    /// PEM paths for server cert/key (required for `listen` with zquic).
    server_cert_pem_path: ?[]const u8 = null,
    server_private_key_pem_path: ?[]const u8 = null,
    allow_insecure: bool = false,
    max_idle_timeout_ms: u32 = 30_000,
    max_udp_payload: u32 = 1350,
};

pub fn logInit(_: []const u8) void {
    // zquic has no global log level API comparable to lsquic; keep hook for callers.
}

pub const QuicEndpoint = struct {
    allocator: *std.mem.Allocator,
    is_server: bool,
    local_addr: std.net.Address,
    resolved_local: ?std.net.Address = null,
    accept_queue: std.ArrayListUnmanaged(*QuicConnection),
    connect_slot: ?*QuicConnection,
    first_alpn: []const u8,
    base_plpmtu: u16,
    sni_z: ?[:0]u8 = null,
    server: ?*io.Server = null,
    client: ?*io.Client = null,
    owns_sock: bool = true,
    temp_cert_path: ?[]const u8 = null,
    temp_key_path: ?[]const u8 = null,
    /// One `QuicConnection` wrapper per active server `conns` slot (indexed).
    server_conn_handles: [io.MAX_CONNECTIONS]?*QuicConnection = [_]?*QuicConnection{null} ** io.MAX_CONNECTIONS,
    client_host_storage: ?[]u8 = null,
    sock: posix.socket_t = -1,

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

    fn recvOneIfAvailable(self: *QuicEndpoint) !bool {
        var buf: [65536]u8 = undefined;
        var peer: std.net.Address = undefined;
        var peer_len: posix.socklen_t = @sizeOf(std.net.Address);
        const n = posix.recvfrom(self.sock, &buf, 0, &peer.any, &peer_len) catch |err| switch (err) {
            error.WouldBlock => return false,
            else => |e| return e,
        };
        if (n == 0) return false;

        if (self.server) |srv| {
            if (isWildcardLocal(self.local_addr)) {
                if (self.resolved_local == null) {
                    self.resolved_local = resolveLocalForWildcard(self.local_addr, peer);
                }
            }
            srv.feedPacket(buf[0..n], peer);
            srv.processPendingWork();
        } else if (self.client) |cli| {
            cli.feedPacket(buf[0..n]);
            cli.processPendingWork(cli.conn.peer);
            if (self.connect_slot) |qc| {
                qc.dispatchNewIncomingStreams();
            }
        }
        self.scanServerAcceptsAndStreams();
        return true;
    }

    fn scanServerAcceptsAndStreams(self: *QuicEndpoint) void {
        const srv = self.server orelse return;
        for (&srv.conns, 0..) |*slot, i| {
            if (slot.*) |*conn| {
                if (conn.phase == .connected and conn.has_app_keys) {
                    if (self.server_conn_handles[i] == null) {
                        const qc = self.allocator.create(QuicConnection) catch continue;
                        qc.* = QuicConnection.initServer(self, i);
                        self.server_conn_handles[i] = qc;
                        self.accept_queue.append(self.allocator.*, qc) catch {};
                    }
                    if (self.server_conn_handles[i]) |qc| {
                        qc.dispatchNewIncomingStreams();
                    }
                }
            }
        }
    }
};

pub const QuicConnection = struct {
    pub const Stream = struct {
        conn: *QuicConnection,
        stream_id: u64,
        read_buf: std.ArrayListUnmanaged(u8),
        write_buf: std.ArrayListUnmanaged(u8),
        write_off: usize,
        stream_send_off: u64 = 0,
        is_incoming: bool,
        reset_how: ?i32 = null,

        pub fn deinit(self: *Stream) void {
            const a = self.conn.ep.allocator.*;
            self.read_buf.deinit(a);
            self.write_buf.deinit(a);
        }
    };

    ep: *QuicEndpoint,
    hsk_ok: bool,
    is_client: bool,
    server: ?*io.Server = null,
    server_slot: ?usize = null,
    client: ?*io.Client = null,
    incoming_streams: std.ArrayListUnmanaged(*Stream),
    incoming_uni_streams: std.ArrayListUnmanaged(*Stream),
    streams_owned: std.ArrayListUnmanaged(*Stream),
    dispatched_incoming: std.AutoHashMap(u64, void),

    fn initServer(ep: *QuicEndpoint, slot: usize) QuicConnection {
        return .{
            .ep = ep,
            .hsk_ok = true,
            .is_client = false,
            .server = ep.server,
            .server_slot = slot,
            .client = null,
            .incoming_streams = .{},
            .incoming_uni_streams = .{},
            .streams_owned = .{},
            .dispatched_incoming = std.AutoHashMap(u64, void).init(ep.allocator.*),
        };
    }

    pub fn freeAllStreams(self: *QuicConnection) void {
        const a = self.ep.allocator.*;
        self.incoming_streams.clearAndFree(a);
        self.incoming_uni_streams.clearAndFree(a);
        for (self.streams_owned.items) |st| {
            st.deinit();
            a.destroy(st);
        }
        self.streams_owned.clearAndFree(a);
        self.dispatched_incoming.deinit();
    }

    fn initClient(ep: *QuicEndpoint, cli: *io.Client) QuicConnection {
        return .{
            .ep = ep,
            .hsk_ok = true,
            .is_client = true,
            .server = null,
            .server_slot = null,
            .client = cli,
            .incoming_streams = .{},
            .incoming_uni_streams = .{},
            .streams_owned = .{},
            .dispatched_incoming = std.AutoHashMap(u64, void).init(ep.allocator.*),
        };
    }

    fn connStatePtr(self: *QuicConnection) ?*io.ConnState {
        if (self.is_client) return &self.client.?.conn;
        const srv = self.server orelse return null;
        const si = self.server_slot orelse return null;
        if (srv.conns[si]) |*c| return c;
        return null;
    }

    pub fn connStatePtrConst(self: *const QuicConnection) ?*const io.ConnState {
        if (self.is_client) {
            const c = self.client orelse return null;
            return &c.conn;
        }
        const srv = self.server orelse return null;
        const si = self.server_slot orelse return null;
        if (srv.conns[si]) |*c| return c;
        return null;
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

    pub fn dispatchNewIncomingStreams(self: *QuicConnection) void {
        const a = self.ep.allocator.*;
        if (self.is_client) {
            const c = self.client orelse return;
            for (&c.raw_app_recv) |*slot| {
                if (!slot.active) continue;
                self.dispatchOneIncomingSlot(a, slot.stream_id) catch return;
            }
        } else {
            const cs = self.connStatePtr() orelse return;
            for (&cs.raw_app_streams) |*slot| {
                if (!slot.active) continue;
                self.dispatchOneIncomingSlot(a, slot.stream_id) catch return;
            }
        }
    }

    fn dispatchOneIncomingSlot(self: *QuicConnection, a: std.mem.Allocator, sid: u64) !void {
        const gop = try self.dispatched_incoming.getOrPut(sid);
        if (gop.found_existing) return;

        const st = try a.create(Stream);
        st.* = .{
            .conn = self,
            .stream_id = sid,
            .read_buf = .{},
            .write_buf = .{},
            .write_off = 0,
            .is_incoming = true,
        };
        self.streams_owned.append(a, st) catch {
            _ = self.dispatched_incoming.remove(sid);
            st.deinit();
            a.destroy(st);
            return;
        };
        if (self.is_client) {
            if (sid % 4 == 3) {
                try self.incoming_uni_streams.append(a, st);
            } else if (sid % 4 == 1) {
                try self.incoming_streams.append(a, st);
            }
        } else {
            if (sid % 4 == 2) {
                try self.incoming_uni_streams.append(a, st);
            } else if (sid % 4 == 0) {
                try self.incoming_streams.append(a, st);
            }
        }
    }
};

pub const QuicStream = QuicConnection.Stream;

fn parseBindAddr(s: []const u8) !std.net.Address {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.BadAddress;
    const host = s[0..colon];
    const port = try std.fmt.parseInt(u16, s[colon + 1 ..], 10);
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') {
        return try std.net.Address.parseIp(host[1 .. host.len - 1], port);
    }
    return try std.net.Address.parseIp(host, port);
}

fn resolveRepoPath(allocator: std.mem.Allocator, rel: []const u8) ![]const u8 {
    const cwd = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);
    return std.fs.path.resolve(allocator, &.{ cwd, rel });
}

pub fn endpointInit(allocator: *std.mem.Allocator, bind_s: []const u8, qc: *QuicConfig) !*QuicEndpoint {
    const addr = try parseBindAddr(bind_s);
    const is_server = qc.server_cert_pem_path != null;

    const ep = try allocator.create(QuicEndpoint);
    errdefer allocator.destroy(ep);

    const first_alpn = qc.alpn.*[0];

    if (is_server) {
        const cert_path = qc.server_cert_pem_path orelse return error.TlsInit;
        const key_path = qc.server_private_key_pem_path orelse return error.TlsInit;
        const cert_abs = try resolveRepoPath(allocator.*, cert_path);
        errdefer allocator.free(cert_abs);
        const key_abs = try resolveRepoPath(allocator.*, key_path);
        errdefer allocator.free(key_abs);

        const sock = try posix.socket(addr.any.family, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, posix.IPPROTO.UDP);
        errdefer posix.close(sock);
        const reuse: c_int = 1;
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuse));
        try posix.bind(sock, &addr.any, addr.getOsSockLen());

        var local_addr: std.net.Address = undefined;
        var la_len: posix.socklen_t = @sizeOf(std.net.Address);
        try posix.getsockname(sock, &local_addr.any, &la_len);

        const scfg = io.ServerConfig{
            .port = addr.getPort(),
            .cert_path = cert_abs,
            .key_path = key_abs,
            .alpn = first_alpn,
            .raw_application_streams = true,
            .http09 = false,
            .http3 = false,
        };

        const srv = try io.Server.initFromSocket(allocator.*, scfg, sock, true);
        ep.* = .{
            .allocator = allocator,
            .is_server = true,
            .local_addr = local_addr,
            .accept_queue = .{},
            .connect_slot = null,
            .first_alpn = first_alpn,
            .base_plpmtu = @truncate(qc.max_udp_payload),
            .server = srv,
            .owns_sock = true,
            .sock = sock,
            .temp_cert_path = cert_abs,
            .temp_key_path = key_abs,
        };
        return ep;
    }

    const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, posix.IPPROTO.UDP);
    errdefer posix.close(sock);
    try posix.bind(sock, &addr.any, addr.getOsSockLen());
    var local_addr: std.net.Address = undefined;
    var la_len: posix.socklen_t = @sizeOf(std.net.Address);
    try posix.getsockname(sock, &local_addr.any, &la_len);

    const cli = try allocator.create(io.Client);
    errdefer allocator.destroy(cli);
    cli.* = try io.Client.initFromSocket(allocator.*, .{
        .host = "127.0.0.1",
        .port = 443,
        .urls = &.{},
        .alpn = first_alpn,
        .raw_application_streams = true,
        .http09 = false,
        .http3 = false,
    }, sock, true);

    ep.* = .{
        .allocator = allocator,
        .is_server = false,
        .local_addr = local_addr,
        .accept_queue = .{},
        .connect_slot = null,
        .first_alpn = first_alpn,
        .base_plpmtu = @truncate(qc.max_udp_payload),
        .client = cli,
        .owns_sock = true,
        .sock = sock,
    };
    return ep;
}

pub fn endpointDeinit(ep: *QuicEndpoint) void {
    ep.accept_queue.deinit(ep.allocator.*);
    for (&ep.server_conn_handles) |*maybe| {
        if (maybe.*) |qc| {
            qc.freeAllStreams();
            ep.allocator.destroy(qc);
            maybe.* = null;
        }
    }
    if (ep.connect_slot) |q| {
        q.freeAllStreams();
        ep.allocator.destroy(q);
        ep.connect_slot = null;
    }
    if (ep.server) |srv| {
        srv.deinit();
    }
    if (ep.client) |cli| {
        cli.deinit();
        ep.allocator.destroy(cli);
    }
    if (ep.temp_cert_path) |p| ep.allocator.free(p);
    if (ep.temp_key_path) |p| ep.allocator.free(p);
    if (ep.sni_z) |s| ep.allocator.free(s);
    if (ep.client_host_storage) |s| ep.allocator.free(s);
    ep.allocator.destroy(ep);
}

pub fn endpointInitFromFd(
    allocator: *std.mem.Allocator,
    sock: posix.socket_t,
    local_addr: std.net.Address,
    qc: *QuicConfig,
) !*QuicEndpoint {
    const first_alpn = qc.alpn.*[0];
    const cert_path = qc.server_cert_pem_path orelse return error.TlsInit;
    const key_path = qc.server_private_key_pem_path orelse return error.TlsInit;
    const cert_abs = try resolveRepoPath(allocator.*, cert_path);
    errdefer allocator.free(cert_abs);
    const key_abs = try resolveRepoPath(allocator.*, key_path);
    errdefer allocator.free(key_abs);

    const scfg = io.ServerConfig{
        .port = local_addr.getPort(),
        .cert_path = cert_abs,
        .key_path = key_abs,
        .alpn = first_alpn,
        .raw_application_streams = true,
        .http09 = false,
        .http3 = false,
    };

    const srv = try io.Server.initFromSocket(allocator.*, scfg, sock, false);
    const ep = try allocator.create(QuicEndpoint);
    ep.* = .{
        .allocator = allocator,
        .is_server = true,
        .local_addr = local_addr,
        .accept_queue = .{},
        .connect_slot = null,
        .first_alpn = first_alpn,
        .base_plpmtu = @truncate(qc.max_udp_payload),
        .server = srv,
        .owns_sock = false,
        .sock = sock,
        .temp_cert_path = cert_abs,
        .temp_key_path = key_abs,
    };
    return ep;
}

pub fn feedPacket(ep: *QuicEndpoint, data: []const u8, peer: std.net.Address, local: std.net.Address) void {
    _ = local;
    if (ep.server) |srv| {
        srv.feedPacket(data, peer);
        srv.processPendingWork();
    }
    ep.scanServerAcceptsAndStreams();
}

pub fn processEngineOnly(ep: *QuicEndpoint) void {
    if (ep.server) |srv| srv.processPendingWork();
    ep.scanServerAcceptsAndStreams();
}

pub fn connect(ep: *QuicEndpoint, remote_s: []const u8, hostname: []const u8) !*QuicConnection {
    ep.connect_slot = null;
    const cli = ep.client orelse return error.ConnectFailed;
    const remote = try parseBindAddr(remote_s);
    if (ep.sni_z) |old| ep.allocator.free(old);
    const hz = try ep.allocator.allocSentinel(u8, hostname.len, 0);
    @memcpy(hz[0..hostname.len], hostname);
    ep.sni_z = hz;

    if (ep.client_host_storage) |s| ep.allocator.free(s);
    ep.client_host_storage = try ep.allocator.dupe(u8, hostname);
    cli.config.host = ep.client_host_storage.?;
    cli.config.port = remote.getPort();
    cli.conn.peer = remote;

    try cli.startHandshake(remote);

    const qc = try ep.allocator.create(QuicConnection);
    qc.* = QuicConnection.initClient(ep, cli);
    ep.connect_slot = qc;
    return qc;
}

pub fn destroy(ep: *QuicEndpoint, conn: *QuicConnection) void {
    _ = ep;
    _ = conn;
    // zquic does not expose a small public connection-close API; rely on endpoint deinit.
}

pub fn poll(ep: *QuicEndpoint, timeout_ms: u32) !void {
    if (try ep.waitReadable(timeout_ms)) {
        while (try ep.recvOneIfAvailable()) {}
    }
    if (ep.server) |srv| srv.processPendingWork();
    if (ep.client) |cli| {
        cli.processPendingWork(cli.conn.peer);
        if (ep.connect_slot) |qc| {
            qc.dispatchNewIncomingStreams();
        }
    }
    ep.scanServerAcceptsAndStreams();
    if (timeout_ms == 0) {
        std.Thread.sleep(50 * std.time.ns_per_us);
    }
}

pub fn tryAccept(ep: *QuicEndpoint) ?*QuicConnection {
    if (ep.accept_queue.items.len == 0) return null;
    return ep.accept_queue.swapRemove(0);
}

fn connHandshakeReady(conn: *const QuicConnection) bool {
    const cs = conn.connStatePtrConst() orelse return false;
    return cs.phase == .connected and cs.has_app_keys;
}

pub fn handshakeComplete(conn: *const QuicConnection) bool {
    return connHandshakeReady(conn);
}

pub fn getNegotiatedAlpn(conn: *const QuicConnection) ?[]const u8 {
    if (!connHandshakeReady(conn)) return null;
    return conn.ep.first_alpn;
}

pub fn tryAcceptIncomingStream(conn: *QuicConnection) ?*QuicStream {
    if (conn.incoming_streams.items.len == 0) return null;
    return conn.incoming_streams.swapRemove(0);
}

pub fn tryAcceptIncomingUniStream(conn: *QuicConnection) ?*QuicStream {
    if (conn.incoming_uni_streams.items.len == 0) return null;
    return conn.incoming_uni_streams.swapRemove(0);
}

pub fn streamMake(conn: *QuicConnection, poll_peer: ?*QuicEndpoint) !*QuicStream {
    if (!connHandshakeReady(conn)) return error.HandshakeNotComplete;
    const alloc = conn.ep.allocator.*;
    const sid = if (conn.client) |c| blk: {
        break :blk io.rawAllocateNextLocalBidiStream(&c.conn);
    } else blk: {
        const cs = conn.connStatePtr() orelse return error.StreamCreateFailed;
        break :blk io.rawAllocateNextLocalBidiStream(cs);
    };
    const qs = try alloc.create(QuicStream);
    qs.* = .{
        .conn = conn,
        .stream_id = sid,
        .read_buf = .{},
        .write_buf = .{},
        .write_off = 0,
        .is_incoming = false,
    };
    try conn.streams_owned.append(alloc, qs);
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        try poll(conn.ep, 0);
        if (poll_peer) |p| try poll(p, 0);
    }
    return qs;
}

const max_stream_chunk: usize = 1200;

pub fn streamMakeUni(conn: *QuicConnection, poll_peer: ?*QuicEndpoint) !*QuicStream {
    if (!connHandshakeReady(conn)) return error.HandshakeNotComplete;
    const alloc = conn.ep.allocator.*;
    const qs = try alloc.create(QuicStream);
    const sid = if (conn.client) |c| blk: {
        break :blk io.rawAllocateNextLocalUniStream(&c.conn);
    } else blk: {
        const cs = conn.connStatePtr() orelse return error.StreamCreateFailed;
        break :blk io.rawAllocateNextLocalUniStream(cs);
    };
    qs.* = .{
        .conn = conn,
        .stream_id = sid,
        .read_buf = .{},
        .write_buf = .{},
        .write_off = 0,
        .stream_send_off = 0,
        .is_incoming = false,
    };
    try conn.streams_owned.append(alloc, qs);
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        try poll(conn.ep, 0);
        if (poll_peer) |p| try poll(p, 0);
    }
    return qs;
}

pub fn streamCancelWrite(st: *QuicStream) void {
    _ = st;
}

pub fn streamCancelRead(st: *QuicStream) void {
    _ = st;
}

pub fn streamQueueWrite(st: *QuicStream, data: []const u8) !void {
    try st.write_buf.appendSlice(st.conn.ep.allocator.*, data);
}

pub fn streamDrainWrites(st: *QuicStream, peer: *QuicEndpoint, max_rounds: u32) !void {
    var r: u32 = 0;
    while (st.write_off < st.write_buf.items.len and r < max_rounds) : (r += 1) {
        const rest = st.write_buf.items[st.write_off..];
        const take = @min(rest.len, max_stream_chunk);
        const fin = take == rest.len;
        if (st.conn.client) |c| {
            c.sendRawStreamData(st.stream_id, st.stream_send_off, rest[0..take], fin);
        } else {
            const srv = st.conn.server orelse return error.StreamWriteTimeout;
            const cs = st.conn.connStatePtr() orelse return error.StreamWriteTimeout;
            srv.sendRawStreamData(cs, st.stream_id, st.stream_send_off, rest[0..take], fin);
        }
        st.stream_send_off += take;
        st.write_off += take;
        try poll(st.conn.ep, 0);
        try poll(peer, 0);
    }
    if (st.write_off < st.write_buf.items.len) return error.StreamWriteTimeout;
    st.write_buf.clearRetainingCapacity();
    st.write_off = 0;
}

pub fn streamShutdownWrite(st: *QuicStream) void {
    _ = st;
}

pub fn streamReadSlice(st: *const QuicStream) []const u8 {
    if (st.is_incoming) {
        if (st.conn.client) |c| {
            return c.rawAppRecvBuffer(st.stream_id) orelse &.{};
        }
        const cs = st.conn.connStatePtrConst() orelse return &.{};
        return io.rawAppRecvBuffer(@constCast(cs), st.stream_id) orelse &.{};
    }
    return st.read_buf.items;
}

pub fn streamConsumeReadPrefix(st: *QuicStream, n: usize) !void {
    if (n > st.read_buf.items.len) return error.StreamReadUnderflow;
    try st.read_buf.replaceRange(st.conn.ep.allocator.*, 0, n, &.{});
}
