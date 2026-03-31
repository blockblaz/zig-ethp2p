//! QUIC transport shape for ethp2p-style EC broadcast (reference: `github.com/ethp2p/ethp2p` `sim/host.go`).
//!
//! ethp2p uses **quic-go** with ALPN **`eth-ec-broadcast`**, a long `MaxIdleTimeout`, and high stream
//! limits for per-chunk uni-streams. This repository does not ship a QUIC stack in-tree yet; the
//! types below anchor configuration and entry points for a future integration.
//!
//! **Next steps (production path):**
//!
//! - Link a TLS 1.3 + QUIC v1 implementation. One candidate is [`gitlab.com/devnw/zig/quic`](https://gitlab.com/devnw/zig/quic)
//!   (Zig **0.15.1+**, OpenSSL `ssl`/`crypto` on non-Windows in its upstream `build.zig`).
//! - Drive **BCAST / SESS / CHUNK** streams using `wire.*` framing on top of QUIC streams (or datagrams if spec allows).
//! - CI: install OpenSSL dev headers where the QUIC dependency is built; keep default `zig build test` free of that link until the integration is opt-in (e.g. `build.zig` `-Denable-quic`).
//!
//! Until then, `listen` / `dial` return `error.TransportNotImplemented`.

const std = @import("std");
const builtin = @import("builtin");

/// Application-Layer Protocol Negotiation identifier used by ethp2p’s QUIC host (`NextProtos`).
pub const alpn_eth_ec_broadcast: []const u8 = "eth-ec-broadcast";

/// Tunables mirroring the intent of ethp2p `sim/host.go` `defaultQuicConfig` (not wire-identical to quic-go).
pub const EthEcQuicConfig = struct {
    /// Effectively “disable idle close” — ethp2p uses a one-year cap because quic-go rejects `MaxInt64`.
    max_idle_timeout_ns: u64 = 365 * std.time.ns_per_day,
    max_incoming_streams: u32 = 16_384,
    max_incoming_uni_streams: u32 = 16_384,

    pub fn default() EthEcQuicConfig {
        return .{};
    }
};

pub const ListenAddress = struct {
    host: []const u8,
    port: u16,
};

/// Placeholder listener; will wrap a real QUIC `Listener` once a stack is linked.
pub const EthEcQuicListener = struct {
    _phantom: u8 = 0,
};

/// Returns when a QUIC stack is integrated and bound to `address`.
pub fn listen(_: EthEcQuicConfig, _: ListenAddress) error{TransportNotImplemented}!EthEcQuicListener {
    return error.TransportNotImplemented;
}

/// Returns when QUIC dial + TLS handshake to `remote` is implemented.
pub fn dial(_: EthEcQuicConfig, _: ListenAddress) error{TransportNotImplemented}!void {
    return error.TransportNotImplemented;
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
