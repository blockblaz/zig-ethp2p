//! Gossipsub-side message envelope and default topic id used by ethp2p’s simnet driver.
//! Matches `encodeGossipsubMessage` / `decodeGossipsubMessage` / `gossipsubChannelID` in
//! [strategy_gossipsub.go](https://github.com/ethp2p/ethp2p/blob/main/sim/strategy_gossipsub.go).

const std = @import("std");

const Allocator = std.mem.Allocator;

/// Same string as Go `gossipsubChannelID` (`sim/strategy_gossipsub.go`).
pub const default_topic = "broadcast-test";

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
