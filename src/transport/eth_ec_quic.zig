//! QUIC transport for ethp2p-style EC broadcast (reference: `github.com/ethp2p/ethp2p` `sim/host.go`).
//!
//! Links lsquic + BoringSSL via `vendor/lsquic_zig` (always compiled — no build flag needed).
//! Run `zig build test-quic` for handshake + BCAST/SESS stream smoke tests.

const std = @import("std");
const builtin = @import("builtin");
const common = @import("eth_ec_quic_common.zig");
const quic = @import("quic");

pub const alpn_eth_ec_broadcast = common.alpn_eth_ec_broadcast;
pub const EthEcQuicConfig = common.EthEcQuicConfig;
pub const ListenAddress = common.ListenAddress;

/// Re-export so callers outside the zig-ethp2p package can name the type.
pub const QuicEndpoint = quic.QuicEndpoint;

/// Initialise lsquic logging to stderr at `level` (e.g. `"debug"`, `"info"`, `"warn"`).
///
/// This is the programmatic counterpart to the `ZIG_ETHP2P_LSQUIC_LOG` / `LSQUIC_LOG_LEVEL`
/// environment variables.  Either mechanism may be used; calling `logInit` wins over the
/// env vars when both are present because `lsquic_set_log_level` is idempotent and the last
/// call takes effect.
pub fn logInit(level: []const u8) void {
    quic.logInit(level);
}

pub const EthEcQuicListener = struct {
    ep: *quic.QuicEndpoint,
    /// Same as `ListenAddress.port` passed to `listen`.
    port: u16,
    allocator: *std.mem.Allocator,

    pub fn deinit(self: *EthEcQuicListener) void {
        quic.endpointDeinit(self.ep);
    }

    pub fn localPort(self: *const EthEcQuicListener) u16 {
        return self.port;
    }
};

/// Binds a QUIC listener on `address`. Caller must drive `quic.poll` on the underlying
/// endpoint (and the peer when using `quic.streamMake` on loopback).
/// `allocator` must outlive the listener until `deinit`.
/// Returns `error.MissingServerIdentity` when server TLS material is absent.
pub fn listen(allocator: *std.mem.Allocator, config: EthEcQuicConfig, address: ListenAddress) !EthEcQuicListener {
    const enabled = @import("eth_ec_quic_enabled.zig");
    const ep = try enabled.listenImpl(allocator, config, address);
    return .{ .ep = ep, .port = address.port, .allocator = allocator };
}

/// Dials `remote` from an ephemeral local UDP bind, completes the TLS handshake,
/// verifies ALPN, then closes the connection.
pub fn dial(allocator: *std.mem.Allocator, config: EthEcQuicConfig, remote: ListenAddress) !void {
    const enabled = @import("eth_ec_quic_enabled.zig");
    return enabled.dialImpl(allocator, config, remote);
}

/// Create a QUIC listener on an already-bound external socket fd.
/// The caller retains ownership of `fd`; `deinit` on the returned listener will not close it.
/// `local_addr` must reflect the address the fd is bound to.
pub fn listenOnFd(
    allocator: *std.mem.Allocator,
    fd: std.posix.fd_t,
    local_addr: std.net.Address,
    config: EthEcQuicConfig,
) !EthEcQuicListener {
    const enabled = @import("eth_ec_quic_enabled.zig");
    const ep = try enabled.listenImplFromFd(allocator, fd, local_addr, config);
    return .{ .ep = ep, .port = local_addr.getPort(), .allocator = allocator };
}

/// Drive one poll round on the listener's QUIC endpoint.
/// `timeout_ms` is the maximum time to block waiting for I/O events.
pub fn pollListener(listener: *EthEcQuicListener, timeout_ms: u32) !void {
    try quic.poll(listener.ep, timeout_ms);
}

/// Feed a datagram received on a shared socket into the QUIC engine.
/// Call `processEngineOnly` after draining all packets.
pub fn feedPacket(
    listener: *EthEcQuicListener,
    data: []const u8,
    peer: std.net.Address,
    local: std.net.Address,
) void {
    quic.feedPacket(listener.ep, data, peer, local);
}

/// Run pending QUIC timers and flush outbound packets without reading from the socket.
/// Use this when a shared UDP socket owns the recv loop.
pub fn processEngineOnly(listener: *EthEcQuicListener) void {
    quic.processEngineOnly(listener.ep);
}

test "ALPN matches ethp2p QUIC host" {
    try std.testing.expectEqualStrings("eth-ec-broadcast", alpn_eth_ec_broadcast);
}

test "default QUIC-ish config has ethp2p-scale stream headroom" {
    const c = EthEcQuicConfig.default();
    try std.testing.expectEqual(@as(u32, 16_384), c.max_incoming_streams);
    try std.testing.expectEqual(@as(u32, 16_384), c.max_incoming_uni_streams);
    try std.testing.expect(c.max_idle_timeout_ns >= std.time.ns_per_day);
}

test "UDP bind ephemeral (bootstrap for future QUIC socket)" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    defer std.posix.close(sock);

    const any = try std.net.Address.parseIp("127.0.0.1", 0);
    try std.posix.bind(sock, &any.any, any.getOsSockLen());
}

test {
    _ = @import("eth_ec_quic_enabled.zig");
}
