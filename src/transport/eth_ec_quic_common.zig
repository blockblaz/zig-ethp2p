//! Shared types for `eth_ec_quic` (no QUIC dependency).

const std = @import("std");

/// Application-Layer Protocol Negotiation identifier used by ethp2p’s QUIC host (`NextProtos`).
pub const alpn_eth_ec_broadcast: []const u8 = "eth-ec-broadcast";

/// Tunables mirroring the intent of ethp2p `sim/host.go` `defaultQuicConfig` (not wire-identical to quic-go).
pub const EthEcQuicConfig = struct {
    /// Effectively “disable idle close” — ethp2p uses a one-year cap because quic-go rejects `MaxInt64`.
    max_idle_timeout_ns: u64 = 365 * std.time.ns_per_day,
    max_incoming_streams: u32 = 16_384,
    max_incoming_uni_streams: u32 = 16_384,

    /// TLS: self-signed or CA-issued server certificate (DER), for `listen`.
    server_certificate_der: ?[]const u8 = null,
    /// TLS: PKCS#8 private key (DER), for `listen` (Ed25519 or P-256 as supported by the linked QUIC stack).
    server_private_key_der: ?[]const u8 = null,
    /// Client `dial` only: accept any server certificate (tests and local dev; not for production).
    tls_insecure_skip_verify: bool = false,

    pub fn default() EthEcQuicConfig {
        return .{};
    }
};

pub const ListenAddress = struct {
    host: []const u8,
    port: u16,
};
