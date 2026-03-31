//! Cross-module checks and golden bytes for the gossipsub **sim** path (no libp2p).
//! Keeps `gossipsub_transport`, `gossipsub_broadcast`, and `broadcast.gossip` aligned.

const std = @import("std");
const broadcast_gossip = @import("../broadcast/gossip.zig");
const gossipsub_broadcast = @import("gossipsub_broadcast.zig");
const gossipsub_protocol = @import("gossipsub_protocol.zig");
const gossipsub_transport = @import("gossipsub_transport.zig");

test "golden encode matches expected bytes (Go encodeGossipsubMessage parity)" {
    const gpa = std.testing.allocator;
    const enc = try gossipsub_transport.encodeMessage(gpa, "mid", "payload");
    defer gpa.free(enc);
    try std.testing.expectEqualStrings("mid|payload", enc);
}

test "broadcast.gossip and transport encode identical output" {
    const gpa = std.testing.allocator;
    const a = try gossipsub_transport.encodeMessage(gpa, "a", "b");
    defer gpa.free(a);
    const b = try broadcast_gossip.encodeApplicationPublish(gpa, "a", "b");
    defer gpa.free(b);
    try std.testing.expectEqualSlices(u8, a, b);
}

test "mesh fanout two recipients decode same application payload" {
    const gpa = std.testing.allocator;
    var mesh = gossipsub_protocol.FanoutMesh.init(gpa);
    defer mesh.deinit();

    const topic = gossipsub_transport.default_topic;
    try mesh.subscribe("alice", topic);
    try mesh.subscribe("bob", topic);
    try mesh.subscribe("carol", topic);

    const payload = [_]u8{ 0xde, 0xad };
    try gossipsub_broadcast.encodeAndFanout(&mesh, gpa, "alice", topic, "k1", &payload);

    const names = [_][]const u8{ "bob", "carol" };
    for (names) |who| {
        var inbox: std.ArrayListUnmanaged([]u8) = .{};
        defer {
            for (inbox.items) |s| gpa.free(s);
            inbox.deinit(gpa);
        }
        try mesh.drainPeer(who, &inbox);
        try std.testing.expectEqual(@as(usize, 1), inbox.items.len);
        const dec = try gossipsub_transport.decodeMessage(inbox.items[0]);
        try std.testing.expectEqualStrings("k1", dec.message_id);
        try std.testing.expectEqualSlices(u8, &payload, dec.payload);
    }
}
