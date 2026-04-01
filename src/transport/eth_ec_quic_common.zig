//! Shared types for `eth_ec_quic` (no QUIC dependency).

const std = @import("std");

/// Application-Layer Protocol Negotiation identifier used by ethp2p’s QUIC host (`NextProtos`).
pub const alpn_eth_ec_broadcast: []const u8 = "eth-ec-broadcast";

/// Milliseconds for `quic.poll` while driving endpoints. Passing **0** spins as fast as possible; on macOS that
/// can prevent healthy timer / UDP scheduling and has been observed to end with **SIGKILL** during handshake tests.
pub const quic_poll_drive_timeout_ms: i32 = 1;

/// Wall-clock budget for loopback handshake tests (`std.time.nanoTimestamp()`).
pub const handshake_test_deadline_ns: i128 = 30 * std.time.ns_per_s;

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
    /// Client `dial` only: TLS SNI (Server Name Indication). When null, `dial` uses `remote.host` (often wrong for `127.0.0.1` vs a DNS-named cert).
    tls_server_name: ?[]const u8 = null,

    pub fn default() EthEcQuicConfig {
        return .{};
    }
};

pub const ListenAddress = struct {
    host: []const u8,
    port: u16,
};
