//! Gossipsub **sim** publish envelope for raw application payloads (not RS chunk streams).
//! RS broadcast uses `wire.*` and `layer.rs_strategy`; this module is the same shape as Go
//! `encodeGossipsubMessage` for app-level bytes.

const std = @import("std");
const gossipsub_transport = @import("../sim/gossipsub_transport.zig");

pub const default_topic = gossipsub_transport.default_topic;

pub fn encodeApplicationPublish(allocator: std.mem.Allocator, message_id: []const u8, payload: []const u8) ![]u8 {
    return gossipsub_transport.encodeMessage(allocator, message_id, payload);
}
