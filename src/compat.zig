//! Compatibility shims for the Zig 0.15 → 0.16 standard-library reorg.
//!
//! Zig 0.16 removed the high-level wrappers `std.net`, `std.crypto.random`,
//! `std.process.getEnvVarOwned`, and the `socket`/`bind`/`sendto`/`recvfrom`/
//! `close` helpers from `std.posix` (all folded into the new `std.Io`
//! abstraction), and dropped `std.Thread.Mutex`/`std.Thread.Pool`.
//!
//! zig-ethp2p drives its own poll loop (via zquic) and does not need the
//! `std.Io` async machinery — it just needs the raw syscalls and small value
//! types back. This module reinstates a thin, dependency-free subset, mirroring
//! the approach zquic itself takes in its own `compat.zig`.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const system = posix.system;

inline fn checkRc(rc: anytype) posix.E {
    return posix.errno(rc);
}

// ── socket / bind / sendto / recvfrom / close ───────────────────────────────

pub const SocketError = error{
    AccessDenied,
    AddressFamilyUnsupported,
    ProtocolUnsupportedBySystem,
    ProtocolFamilyUnavailable,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
} || posix.UnexpectedError;

pub fn socket(domain: u32, sock_type: u32, protocol: u32) SocketError!posix.socket_t {
    // `std.posix.SOCK.NONBLOCK`/`CLOEXEC` are Zig-abstract flag bits, not the
    // raw kernel values — the removed `std.posix.socket` translated them. Strip
    // them off the type and apply them with `fcntl` after creation (portable
    // across Linux and Darwin).
    const want_nonblock = (sock_type & posix.SOCK.NONBLOCK) != 0;
    const want_cloexec = (sock_type & posix.SOCK.CLOEXEC) != 0;
    const raw_type = sock_type & ~@as(u32, posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC);

    const rc = system.socket(domain, raw_type, protocol);
    switch (checkRc(rc)) {
        .SUCCESS => {},
        .ACCES => return error.AccessDenied,
        .AFNOSUPPORT => return error.AddressFamilyUnsupported,
        .INVAL => return error.ProtocolFamilyUnavailable,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        .PROTONOSUPPORT => return error.ProtocolUnsupportedBySystem,
        else => |err| return posix.unexpectedErrno(err),
    }
    const fd: posix.socket_t = @intCast(rc);
    if (want_nonblock) {
        const fl = system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
        const o_nonblock: u32 = @bitCast(posix.O{ .NONBLOCK = true });
        _ = system.fcntl(fd, posix.F.SETFL, fl | o_nonblock);
    }
    if (want_cloexec) {
        const fdfl = system.fcntl(fd, posix.F.GETFD, @as(usize, 0));
        _ = system.fcntl(fd, posix.F.SETFD, fdfl | posix.FD_CLOEXEC);
    }
    return fd;
}

pub const BindError = error{
    AccessDenied,
    AddressInUse,
    AddressNotAvailable,
    AlreadyBound,
    SystemResources,
} || posix.UnexpectedError;

pub fn bind(sock: posix.socket_t, addr: *const posix.sockaddr, len: posix.socklen_t) BindError!void {
    const rc = system.bind(sock, addr, len);
    switch (checkRc(rc)) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .INVAL => return error.AlreadyBound,
        .NOMEM => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub const SendToError = error{
    AccessDenied,
    WouldBlock,
    BrokenPipe,
    MessageTooBig,
    ConnectionResetByPeer,
    NetworkUnreachable,
    NetworkDown,
    HostUnreachable,
    SystemResources,
    SocketUnconnected,
    AddressFamilyUnsupported,
} || posix.UnexpectedError;

pub fn sendto(
    sock: posix.socket_t,
    buf: []const u8,
    flags: u32,
    dest_addr: ?*const posix.sockaddr,
    addrlen: posix.socklen_t,
) SendToError!usize {
    while (true) {
        const rc = system.sendto(sock, buf.ptr, buf.len, flags, dest_addr, addrlen);
        switch (checkRc(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .ACCES => return error.AccessDenied,
            .AGAIN => return error.WouldBlock,
            .PIPE => return error.BrokenPipe,
            .MSGSIZE => return error.MessageTooBig,
            .CONNRESET => return error.ConnectionResetByPeer,
            .NETUNREACH => return error.NetworkUnreachable,
            .NETDOWN => return error.NetworkDown,
            .HOSTUNREACH => return error.HostUnreachable,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .NOTCONN => return error.SocketUnconnected,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

pub const RecvFromError = error{
    WouldBlock,
    SystemResources,
    ConnectionResetByPeer,
    ConnectionRefused,
    SocketUnconnected,
} || posix.UnexpectedError;

pub fn recvfrom(
    sock: posix.socket_t,
    buf: []u8,
    flags: u32,
    src_addr: ?*posix.sockaddr,
    addrlen: ?*posix.socklen_t,
) RecvFromError!usize {
    while (true) {
        const rc = system.recvfrom(sock, buf.ptr, buf.len, flags, src_addr, addrlen);
        switch (checkRc(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNRESET => return error.ConnectionResetByPeer,
            .CONNREFUSED => return error.ConnectionRefused,
            .NOTCONN => return error.SocketUnconnected,
            .NOMEM, .NOBUFS => return error.SystemResources,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

pub fn close(sock: posix.socket_t) void {
    _ = system.close(sock);
}

/// Sleep for `ns` nanoseconds (replaces the removed `std.Thread.sleep`, which
/// in 0.16 became `std.Io.sleep` and requires an `Io` instance).
pub fn sleepNs(ns: u64) void {
    var req: posix.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    var rem: posix.timespec = undefined;
    while (true) {
        const rc = system.nanosleep(&req, &rem);
        if (posix.errno(rc) == .INTR) {
            req = rem;
            continue;
        }
        return;
    }
}

pub const ConnectError = error{
    AccessDenied,
    AddressInUse,
    AddressNotAvailable,
    ConnectionRefused,
    ConnectionResetByPeer,
    NetworkUnreachable,
    HostUnreachable,
    Timeout,
    AlreadyConnected,
    WouldBlock,
    SystemResources,
} || posix.UnexpectedError;

pub fn connect(sock: posix.socket_t, addr: *const posix.sockaddr, len: posix.socklen_t) ConnectError!void {
    const rc = system.connect(sock, addr, len);
    switch (checkRc(rc)) {
        .SUCCESS => return,
        .ACCES, .PERM => return error.AccessDenied,
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .AGAIN, .INPROGRESS => return error.WouldBlock,
        .ALREADY, .ISCONN => return error.AlreadyConnected,
        .CONNREFUSED => return error.ConnectionRefused,
        .CONNRESET => return error.ConnectionResetByPeer,
        .HOSTUNREACH => return error.HostUnreachable,
        .NETUNREACH => return error.NetworkUnreachable,
        .TIMEDOUT => return error.Timeout,
        .NOMEM, .NOBUFS => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub const GetSockNameError = error{SystemResources} || posix.UnexpectedError;

pub fn getsockname(sock: posix.socket_t, addr: *posix.sockaddr, len: *posix.socklen_t) GetSockNameError!void {
    const rc = system.getsockname(sock, addr, len);
    switch (checkRc(rc)) {
        .SUCCESS => return,
        .NOBUFS => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    }
}

// ── net.Address / Ip4Address / Ip6Address ───────────────────────────────────
//
// Mirrors the pre-0.16 `std.net.Address` ergonomics zig-ethp2p relies on:
// extern union over sockaddr with `.any`, `.in`, `.in6`, `initIp4`, `parseIp`,
// `getPort`, `setPort`, `getOsSockLen`, `eql`.

pub const Address = extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,

    pub fn initIp4(addr: [4]u8, port: u16) Address {
        return .{ .in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, port),
            .addr = @bitCast(addr),
            .zero = [_]u8{0} ** 8,
        } };
    }

    pub fn parseIp4(buf: []const u8, port: u16) !Address {
        var bytes: [4]u8 = undefined;
        var idx: usize = 0;
        var byte: u16 = 0;
        var has_digit = false;
        for (buf) |c| {
            if (c == '.') {
                if (!has_digit or idx >= 3) return error.InvalidIPAddressFormat;
                bytes[idx] = @intCast(byte);
                idx += 1;
                byte = 0;
                has_digit = false;
            } else if (c >= '0' and c <= '9') {
                byte = byte * 10 + (c - '0');
                if (byte > 255) return error.InvalidIPAddressFormat;
                has_digit = true;
            } else {
                return error.InvalidIPAddressFormat;
            }
        }
        if (!has_digit or idx != 3) return error.InvalidIPAddressFormat;
        bytes[3] = @intCast(byte);
        return initIp4(bytes, port);
    }

    pub fn parseIp(buf: []const u8, port: u16) !Address {
        return parseIp4(buf, port);
    }

    pub fn getPort(self: Address) u16 {
        return switch (self.any.family) {
            posix.AF.INET => std.mem.bigToNative(u16, self.in.port),
            posix.AF.INET6 => std.mem.bigToNative(u16, self.in6.port),
            else => 0,
        };
    }

    pub fn setPort(self: *Address, port: u16) void {
        switch (self.any.family) {
            posix.AF.INET => self.in.port = std.mem.nativeToBig(u16, port),
            posix.AF.INET6 => self.in6.port = std.mem.nativeToBig(u16, port),
            else => {},
        }
    }

    pub fn getOsSockLen(self: Address) posix.socklen_t {
        return switch (self.any.family) {
            posix.AF.INET => @sizeOf(posix.sockaddr.in),
            posix.AF.INET6 => @sizeOf(posix.sockaddr.in6),
            else => 0,
        };
    }

    pub fn eql(a: Address, b: Address) bool {
        if (a.any.family != b.any.family) return false;
        return switch (a.any.family) {
            posix.AF.INET => a.in.port == b.in.port and a.in.addr == b.in.addr,
            posix.AF.INET6 => blk: {
                if (a.in6.port != b.in6.port) break :blk false;
                break :blk std.mem.eql(u8, &a.in6.addr, &b.in6.addr);
            },
            else => false,
        };
    }
};

/// Minimal stand-in for `std.net.Ip4Address` — zig-ethp2p only constructs it
/// from raw bytes (ENR `ip` field) and reads back the address octets.
pub const Ip4Address = struct {
    sa: posix.sockaddr.in,

    pub fn init(addr: [4]u8, port: u16) Ip4Address {
        return .{ .sa = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, port),
            .addr = @bitCast(addr),
            .zero = [_]u8{0} ** 8,
        } };
    }
};

/// Minimal stand-in for `std.net.Ip6Address` (ENR `ip6` field).
pub const Ip6Address = struct {
    sa: posix.sockaddr.in6,

    pub fn init(addr: [16]u8, port: u16) Ip6Address {
        return .{ .sa = .{
            .family = posix.AF.INET6,
            .port = std.mem.nativeToBig(u16, port),
            .flowinfo = 0,
            .addr = addr,
            .scope_id = 0,
        } };
    }
};

// ── CSPRNG (replaces removed `std.crypto.random`) ───────────────────────────

fn osRandomBytes(buf: []u8) void {
    if (comptime builtin.os.tag == .linux and !builtin.link_libc) {
        var off: usize = 0;
        while (off < buf.len) {
            const rc = std.os.linux.getrandom(buf.ptr + off, buf.len - off, 0);
            const e = posix.errno(rc);
            if (e == .SUCCESS) {
                off += @intCast(rc);
            } else if (e == .INTR) {
                continue;
            } else {
                @panic("getrandom failed");
            }
        }
    } else if (comptime builtin.os.tag == .linux) {
        var off: usize = 0;
        while (off < buf.len) {
            const n = std.c.getrandom(buf.ptr + off, buf.len - off, 0);
            if (n > 0) {
                off += @intCast(n);
            } else {
                if (posix.errno(n) == .INTR) continue;
                @panic("getrandom failed");
            }
        }
    } else {
        std.c.arc4random_buf(buf.ptr, buf.len);
    }
}

const RandomSrc = struct {
    fn fill(_: *const RandomSrc, buf: []u8) void {
        osRandomBytes(buf);
    }
};

var random_src: RandomSrc = .{};

/// Drop-in for the removed `std.crypto.random`. Backed by the OS CSPRNG.
pub const random: std.Random = std.Random.init(&random_src, RandomSrc.fill);

// ── Mutex (replaces removed `std.Thread.Mutex`) ─────────────────────────────
//
// A minimal test-and-test-and-set spinlock over `std.atomic.Value`. zig-ethp2p
// only guards short critical sections in the async verify worker path, so a
// spinlock is adequate and needs no `std.Io` instance.

pub const Mutex = struct {
    state: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn lock(self: *Mutex) void {
        while (true) {
            if (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) == null) return;
            while (self.state.load(.monotonic) != 0) {
                std.atomic.spinLoopHint();
            }
        }
    }

    pub fn tryLock(self: *Mutex) bool {
        return self.state.cmpxchgStrong(0, 1, .acquire, .monotonic) == null;
    }

    pub fn unlock(self: *Mutex) void {
        self.state.store(0, .release);
    }
};

// ── WaitGroup / Pool (replace removed `std.Thread.WaitGroup` / `std.Thread.Pool`) ──
//
// zig-ethp2p's threaded work is limited to the async SHA256 verify path. A
// minimal counter-based `WaitGroup` and a spawn-per-job `Pool` (both backed by
// the still-present `std.Thread.spawn`) cover the small API surface used, with
// no `std.Io` instance required. `n_jobs == 0` runs jobs inline on the caller.

pub const WaitGroup = struct {
    counter: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    pub fn start(self: *WaitGroup) void {
        _ = self.counter.fetchAdd(1, .monotonic);
    }

    pub fn finish(self: *WaitGroup) void {
        _ = self.counter.fetchSub(1, .release);
    }

    pub fn wait(self: *WaitGroup) void {
        while (self.counter.load(.acquire) != 0) std.atomic.spinLoopHint();
    }
};

pub const Pool = struct {
    allocator: std.mem.Allocator = undefined,
    n_jobs: usize = 0,
    mu: Mutex = .{},
    threads: std.ArrayList(std.Thread) = .empty,

    pub const Options = struct {
        allocator: std.mem.Allocator,
        n_jobs: ?usize = null,
    };

    pub fn init(self: *Pool, options: Options) !void {
        self.* = .{
            .allocator = options.allocator,
            .n_jobs = options.n_jobs orelse 0,
        };
    }

    pub fn deinit(self: *Pool) void {
        for (self.threads.items) |t| t.join();
        self.threads.deinit(self.allocator);
        self.* = undefined;
    }

    fn track(self: *Pool, t: std.Thread) void {
        self.mu.lock();
        defer self.mu.unlock();
        self.threads.append(self.allocator, t) catch t.detach();
    }

    pub fn spawn(self: *Pool, comptime func: anytype, args: anytype) !void {
        if (self.n_jobs == 0) {
            @call(.auto, func, args);
            return;
        }
        const t = try std.Thread.spawn(.{}, func, args);
        self.track(t);
    }

    pub fn spawnWg(self: *Pool, wg: *WaitGroup, comptime func: anytype, args: anytype) void {
        wg.start();
        if (self.n_jobs == 0) {
            @call(.auto, func, args);
            wg.finish();
            return;
        }
        const Wrap = struct {
            fn run(w: *WaitGroup, inner: @TypeOf(args)) void {
                @call(.auto, func, inner);
                w.finish();
            }
        };
        const t = std.Thread.spawn(.{}, Wrap.run, .{ wg, args }) catch {
            @call(.auto, func, args);
            wg.finish();
            return;
        };
        self.track(t);
    }
};

// ── Environment (replaces removed `std.process.getEnvVarOwned`) ──────────────

pub const GetEnvError = error{ EnvironmentVariableNotFound, OutOfMemory };

/// Returns an owned copy of environment variable `name`, or
/// `error.EnvironmentVariableNotFound` when unset. Linux reads
/// `/proc/self/environ` (no libc required); other targets use libc `getenv`.
pub fn getEnvVarOwned(allocator: std.mem.Allocator, name: []const u8) GetEnvError![]u8 {
    if (comptime builtin.os.tag == .linux) {
        const fd = system.open("/proc/self/environ", posix.O{ .ACCMODE = .RDONLY }, @as(posix.mode_t, 0));
        if (posix.errno(fd) != .SUCCESS) return error.EnvironmentVariableNotFound;
        const handle: posix.fd_t = @intCast(fd);
        defer _ = system.close(handle);

        var contents: std.ArrayList(u8) = .empty;
        defer contents.deinit(allocator);
        var buf: [4096]u8 = undefined;
        while (true) {
            const rc = system.read(handle, &buf, buf.len);
            if (posix.errno(rc) != .SUCCESS) return error.EnvironmentVariableNotFound;
            const n: usize = @intCast(rc);
            if (n == 0) break;
            contents.appendSlice(allocator, buf[0..n]) catch return error.OutOfMemory;
        }
        var entries = std.mem.splitScalar(u8, contents.items, 0);
        while (entries.next()) |entry| {
            const eq = std.mem.indexOfScalar(u8, entry, '=') orelse continue;
            if (std.mem.eql(u8, entry[0..eq], name)) {
                return allocator.dupe(u8, entry[eq + 1 ..]) catch error.OutOfMemory;
            }
        }
        return error.EnvironmentVariableNotFound;
    } else {
        var name_buf: [256]u8 = undefined;
        if (name.len >= name_buf.len) return error.EnvironmentVariableNotFound;
        @memcpy(name_buf[0..name.len], name);
        name_buf[name.len] = 0;
        const val = std.c.getenv(@ptrCast(&name_buf)) orelse return error.EnvironmentVariableNotFound;
        return allocator.dupe(u8, std.mem.span(val)) catch error.OutOfMemory;
    }
}

/// Owned absolute path of the current working directory (replaces the removed
/// `std.fs.cwd().realpathAlloc(".")` / `std.posix.getcwd`).
pub fn getCwdAlloc(allocator: std.mem.Allocator) ![]u8 {
    var buf: [4096]u8 = undefined;
    if (comptime builtin.os.tag == .linux and !builtin.link_libc) {
        const rc = std.os.linux.getcwd(&buf, buf.len);
        if (posix.errno(rc) != .SUCCESS) return error.CurrentWorkingDirectoryUnlinked;
        const path = std.mem.sliceTo(&buf, 0);
        return allocator.dupe(u8, path);
    } else {
        if (std.c.getcwd(&buf, buf.len) == null) return error.CurrentWorkingDirectoryUnlinked;
        return allocator.dupe(u8, std.mem.sliceTo(&buf, 0));
    }
}

test "Address round-trips ipv4 + port" {
    var a = Address.initIp4(.{ 127, 0, 0, 1 }, 30303);
    try std.testing.expectEqual(@as(u16, 30303), a.getPort());
    a.setPort(40404);
    try std.testing.expectEqual(@as(u16, 40404), a.getPort());
    const b = try Address.parseIp("127.0.0.1", 40404);
    try std.testing.expect(a.eql(b));
}

test "Mutex guards a counter across threads" {
    var m: Mutex = .{};
    var n: usize = 0;
    const Ctx = struct {
        fn bump(mu: *Mutex, counter: *usize) void {
            var i: usize = 0;
            while (i < 1000) : (i += 1) {
                mu.lock();
                counter.* += 1;
                mu.unlock();
            }
        }
    };
    const t0 = try std.Thread.spawn(.{}, Ctx.bump, .{ &m, &n });
    const t1 = try std.Thread.spawn(.{}, Ctx.bump, .{ &m, &n });
    t0.join();
    t1.join();
    try std.testing.expectEqual(@as(usize, 2000), n);
}
