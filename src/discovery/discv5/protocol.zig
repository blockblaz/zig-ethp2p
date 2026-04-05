//! discv5 message types (discv5 spec §10).
//!
//! Messages are RLP-encoded, then encrypted with AES-128-GCM using the
//! session key.  Each message begins with a 1-byte request-type field.
//!
//! Implemented types: PING, PONG, FINDNODE, NODES, TALKREQ, TALKRES.
//! Only the type definitions and constants are here; full RLP encode/decode
//! follows the same pattern as enr/enr.zig and is left for phase-2.

const std = @import("std");

// ---------------------------------------------------------------------------
// Message type constants (discv5 spec §10)
// ---------------------------------------------------------------------------

pub const msg_ping: u8 = 0x01;
pub const msg_pong: u8 = 0x02;
pub const msg_findnode: u8 = 0x03;
pub const msg_nodes: u8 = 0x04;
pub const msg_talkreq: u8 = 0x05;
pub const msg_talkres: u8 = 0x06;

// ---------------------------------------------------------------------------
// Protocol parameters
// ---------------------------------------------------------------------------

/// Maximum number of ENRs returned in a single NODES reply.
pub const max_nodes_per_response: usize = 4;

/// Maximum payload size for TALKREQ / TALKRES (discv5 spec recommendation).
pub const max_talk_payload: usize = 1200;

/// Request timeout (how long to wait before re-sending or giving up).
pub const request_timeout_ms: u64 = 500;

/// Maximum number of concurrent in-flight requests per peer.
pub const max_in_flight: usize = 3;

// ---------------------------------------------------------------------------
// Message structs
// ---------------------------------------------------------------------------

/// PING — liveness probe, also carries the sender's current ENR seq.
pub const Ping = struct {
    /// Monotonically increasing request ID.
    request_id: u64,
    /// Sender's current ENR sequence number.
    enr_seq: u64,
};

/// PONG — reply to PING.
pub const Pong = struct {
    request_id: u64,
    enr_seq: u64,
    /// Sender's observed IP address of the recipient (for NAT traversal).
    recipient_ip: std.net.Address,
    recipient_port: u16,
};

/// FINDNODE — request the `k` closest nodes to a given log-distance.
pub const FindNode = struct {
    request_id: u64,
    /// Log-distance values to query (1–256); empty = request own record.
    distances: []const u8,
};

/// NODES — reply to FINDNODE, carrying ENR records.
/// Multiple NODES replies may be sent for a single FINDNODE (total field
/// indicates how many replies to expect).
pub const Nodes = struct {
    request_id: u64,
    /// Total number of NODES packets in this response series.
    total: u8,
    /// RLP-encoded ENR records (each up to 300 bytes).
    enrs: []const []const u8,
};

/// TALKREQ — application-level request (e.g. for custom sub-protocols).
pub const TalkReq = struct {
    request_id: u64,
    /// Protocol identifier (UTF-8 string, e.g. "eth-ec/1").
    protocol: []const u8,
    /// Opaque request payload.
    payload: []const u8,
};

/// TALKRES — reply to TALKREQ.
pub const TalkRes = struct {
    request_id: u64,
    /// Opaque response payload.
    payload: []const u8,
};

// ---------------------------------------------------------------------------
// Protocol identifier for TALKREQ
// ---------------------------------------------------------------------------

/// TALKREQ protocol string for ethp2p capability exchange.
pub const talk_protocol_eth_ec: []const u8 = "eth-ec/1";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "message type constants are distinct" {
    const types = [_]u8{ msg_ping, msg_pong, msg_findnode, msg_nodes, msg_talkreq, msg_talkres };
    for (types, 0..) |a, i| {
        for (types[i + 1 ..]) |b| {
            try std.testing.expect(a != b);
        }
    }
}

test "protocol limits are sensible" {
    try std.testing.expect(max_nodes_per_response > 0);
    try std.testing.expect(max_talk_payload >= 256);
    try std.testing.expect(request_timeout_ms > 0);
}
