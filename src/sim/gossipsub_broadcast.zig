//! Helpers tying `gossipsub_transport` framing to `FanoutMesh` delivery (abstract sim path).

const std = @import("std");
const gossipsub_protocol = @import("gossipsub_protocol.zig");
const gossipsub_transport = @import("gossipsub_transport.zig");

const Allocator = std.mem.Allocator;
pub const FanoutMesh = gossipsub_protocol.FanoutMesh;

/// Encode like Go `GossipsubNode.Publish`, then fan out opaque bytes to topic subscribers (except `from`).
pub fn encodeAndFanout(
    mesh: *FanoutMesh,
    allocator: Allocator,
    from: []const u8,
    topic: []const u8,
    message_id: []const u8,
    payload: []const u8,
) Allocator.Error!void {
    const enc = try gossipsub_transport.encodeMessage(allocator, message_id, payload);
    defer allocator.free(enc);
    try mesh.publishData(from, topic, enc);
}

test "encodeAndFanout roundtrip through mesh" {
    const gpa = std.testing.allocator;
    var mesh = FanoutMesh.init(gpa);
    defer mesh.deinit();

    const topic = gossipsub_transport.default_topic;
    try mesh.subscribe("alice", topic);
    try mesh.subscribe("bob", topic);

    const app = [_]u8{ 1, 2, 3, 4 };
    try encodeAndFanout(&mesh, gpa, "alice", topic, "mid-z", &app);

    var bob_inbox: std.ArrayListUnmanaged([]u8) = .{};
    defer {
        for (bob_inbox.items) |s| gpa.free(s);
        bob_inbox.deinit(gpa);
    }
    try mesh.drainPeer("bob", &bob_inbox);
    try std.testing.expectEqual(@as(usize, 1), bob_inbox.items.len);

    const dec = try gossipsub_transport.decodeMessage(bob_inbox.items[0]);
    try std.testing.expectEqualStrings("mid-z", dec.message_id);
    try std.testing.expectEqualSlices(u8, &app, dec.payload);
}

test "golden sim publish bytes" {
    const gpa = std.testing.allocator;
    const enc = try gossipsub_transport.encodeMessage(gpa, "m", "p");
    defer gpa.free(enc);
    try std.testing.expectEqualSlices(u8, &.{ 'm', '|', 'p' }, enc);
}
