//! Gossipsub wire helpers and protocol parameters from ethp2p's simnet driver.
//! Mirrors `gossipsubChannelID`, `encodeGossipsubMessage`, `decodeGossipsubMessage`,
//! `gossipsubMessageID`, and `newPubSub` params from
//! [strategy_gossipsub.go](https://github.com/ethp2p/ethp2p/blob/main/sim/strategy_gossipsub.go).
//! Parameters are aligned with Prysm `beacon-chain/p2p/pubsub.go` (upstream `db6e941`).

const std = @import("std");

const Allocator = std.mem.Allocator;

/// Same string as Go `gossipsubChannelID` (`sim/strategy_gossipsub.go`).
pub const default_topic = "broadcast-test";

// ---------------------------------------------------------------------------
// Gossipsub network parameters (Go `newPubSub`, Prysm-aligned as of db6e941)
// ---------------------------------------------------------------------------

/// Target mesh degree (Go `params.D`).
pub const mesh_d: u32 = 8;
/// Lower bound on mesh degree — triggers grafting (Go `params.Dlo`).
pub const mesh_d_lo: u32 = 6;
/// Upper bound on mesh degree — triggers pruning (Go `params.Dhi`).
pub const mesh_d_hi: u32 = 12;
/// Lazy-push degree for IHAVE gossip (Go `params.Dlazy`).
pub const mesh_d_lazy: u32 = 6;
/// Heartbeat period in milliseconds (Go `params.HeartbeatInterval = 700ms`).
pub const heartbeat_interval_ms: u64 = 700;
/// How long fanout state is kept without a publish, in milliseconds (Go `params.FanoutTTL = 60s`).
pub const fanout_ttl_ms: u64 = 60_000;
/// Number of heartbeat intervals to keep in the message cache (Go `params.HistoryLength`).
pub const history_length: u32 = 6;
/// Number of cache windows to include in IHAVE gossip (Go `params.HistoryGossip`).
pub const history_gossip: u32 = 3;
/// Maximum gossipsub message size in bytes (Go `pubsub.WithMaxMessageSize(1 << 30)`).
pub const max_message_size: u32 = 1 << 30;
/// Per-peer outbound RPC queue depth (Go `pubsub.WithPeerOutboundQueueSize(600)`).
pub const peer_outbound_queue_size: u32 = 600;
/// Validation queue depth (Go `pubsub.WithValidateQueueSize(600)`).
pub const validate_queue_size: u32 = 600;
/// Messages carry no `from` / `seqno` / `signature` / `key` fields
/// (Go `pubsub.StrictNoSign` + `pubsub.NoAuthor`).
pub const strict_no_sign = true;

pub const DecodeError = error{MissingSeparator};

/// View into `data`; does not allocate.
pub fn decodeMessage(data: []const u8) DecodeError!struct {
    message_id: []const u8,
    payload: []const u8,
} {
    const sep = std.mem.indexOfScalar(u8, data, '|') orelse return error.MissingSeparator;
    return .{
        .message_id = data[0..sep],
        .payload = data[sep + 1 ..],
    };
}

/// Same behavior as Go `gossipsubMessageID`: id slice, or empty if decoding fails.
pub fn messageIdFromPayload(data: []const u8) []const u8 {
    const dec = decodeMessage(data) catch return &.{};
    return dec.message_id;
}

/// Same layout as Go `encodeGossipsubMessage`.
pub fn encodeMessage(allocator: Allocator, message_id: []const u8, payload: []const u8) Allocator.Error![]u8 {
    const out = try allocator.alloc(u8, message_id.len + 1 + payload.len);
    @memcpy(out[0..message_id.len], message_id);
    out[message_id.len] = '|';
    @memcpy(out[message_id.len + 1 ..], payload);
    return out;
}

test "encode and decode roundtrip" {
    const gpa = std.testing.allocator;
    const enc = try encodeMessage(gpa, "mid-1", "payload-bytes");
    defer gpa.free(enc);

    const dec = try decodeMessage(enc);
    try std.testing.expectEqualStrings("mid-1", dec.message_id);
    try std.testing.expectEqualStrings("payload-bytes", dec.payload);
}

test "decode empty message id before separator" {
    const dec = try decodeMessage("|rest");
    try std.testing.expectEqualStrings("", dec.message_id);
    try std.testing.expectEqualStrings("rest", dec.payload);
}

test "decode rejects missing separator" {
    try std.testing.expectError(error.MissingSeparator, decodeMessage("noseparator"));
}

test "messageIdFromPayload matches Go error path" {
    try std.testing.expectEqual(@as(usize, 0), messageIdFromPayload("bad").len);
    try std.testing.expectEqualStrings("x", messageIdFromPayload("x|y"));
}

test "default topic matches reference constant" {
    try std.testing.expectEqualStrings("broadcast-test", default_topic);
}

test "gossipsub params match Prysm-aligned reference (newPubSub db6e941)" {
    try std.testing.expectEqual(@as(u32, 8), mesh_d);
    try std.testing.expectEqual(@as(u32, 6), mesh_d_lo);
    try std.testing.expectEqual(@as(u32, 12), mesh_d_hi);
    try std.testing.expectEqual(@as(u32, 6), mesh_d_lazy);
    try std.testing.expectEqual(@as(u64, 700), heartbeat_interval_ms);
    try std.testing.expectEqual(@as(u64, 60_000), fanout_ttl_ms);
    try std.testing.expectEqual(@as(u32, 6), history_length);
    try std.testing.expectEqual(@as(u32, 3), history_gossip);
    try std.testing.expectEqual(@as(u32, 1 << 30), max_message_size);
    try std.testing.expectEqual(@as(u32, 600), peer_outbound_queue_size);
    try std.testing.expectEqual(@as(u32, 600), validate_queue_size);
    try std.testing.expect(strict_no_sign);
}
