//! QUIC transport for ethp2p-style EC broadcast (reference: `github.com/ethp2p/ethp2p` `sim/host.go`).
//!
//! With **`-Denable-quic`**, this links [`gitlab.com/devnw/zig/quic`](https://gitlab.com/devnw/zig/quic) (TLS 1.3 + QUIC v1) and OpenSSL
//! on non-Windows. Default builds omit that dependency; `listen` / `dial` then return `error.TransportNotImplemented`.
//!
//! Run `zig build test-quic -Denable-quic` (after `libssl-dev` / equivalent) for the handshake smoke test.

const std = @import("std");
const builtin = @import("builtin");
const build_opts = @import("zig_ethp2p_options");
const common = @import("eth_ec_quic_common.zig");

pub const alpn_eth_ec_broadcast = common.alpn_eth_ec_broadcast;
pub const EthEcQuicConfig = common.EthEcQuicConfig;
pub const ListenAddress = common.ListenAddress;

/// When `-Denable-quic` is set, QUIC stream helpers for `wire.*` (BCAST / SESS / CHUNK). Empty otherwise.
pub const wire = if (build_opts.enable_quic)
    @import("eth_ec_quic_wire_enabled.zig")
else
    struct {};

pub const EthEcQuicListener = struct {
    inner: if (build_opts.enable_quic) struct {
        ep: *@import("quic").QuicEndpoint,
        /// Same as `ListenAddress.port` passed to `listen` (0 if you bound an ephemeral port — discovery not exposed yet).
        port: u16,
    } else struct {},
    allocator: *std.mem.Allocator,

    pub fn deinit(self: *EthEcQuicListener) void {
        if (comptime !build_opts.enable_quic) return;
        const quic = @import("quic");
        quic.endpointDeinit(self.inner.ep);
    }

    /// UDP port from `listen`’s `address.port` (0 when an ephemeral port was requested; devnw/quic 0.1.10 does not expose bound-port helpers on the package root).
    pub fn localPort(self: *const EthEcQuicListener) u16 {
        if (comptime !build_opts.enable_quic) return 0;
        return self.inner.port;
    }
};

/// Binds a QUIC listener on `address`. Caller must drive `quic.poll` on the underlying endpoint; with QUIC enabled see `wire` for stream adapters (`QuicIoPair`, `QuicStreamReader` / `QuicStreamWriter`).
/// `allocator` must outlive the listener until `deinit`.
/// Errors include `error.TransportNotImplemented` without `-Denable-quic`, and `error.MissingServerIdentity` when server TLS material is absent.
pub fn listen(allocator: *std.mem.Allocator, config: EthEcQuicConfig, address: ListenAddress) !EthEcQuicListener {
    if (comptime !build_opts.enable_quic) return error.TransportNotImplemented;
    const enabled = @import("eth_ec_quic_enabled.zig");
    const ep = try enabled.listenImpl(allocator, config, address);
    return .{ .inner = .{ .ep = ep, .port = address.port }, .allocator = allocator };
}

/// Dials `remote` from an ephemeral local UDP bind, completes the TLS handshake, verifies ALPN, then closes the connection.
pub fn dial(allocator: *std.mem.Allocator, config: EthEcQuicConfig, remote: ListenAddress) !void {
    if (comptime !build_opts.enable_quic) return error.TransportNotImplemented;
    const enabled = @import("eth_ec_quic_enabled.zig");
    return enabled.dialImpl(allocator, config, remote);
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
    if (comptime build_opts.enable_quic) {
        _ = @import("eth_ec_quic_enabled.zig");
        _ = @import("eth_ec_quic_wire_enabled.zig");
    }
}
