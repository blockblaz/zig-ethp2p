//! Abstract topic fanout and per-peer inboxes (no libp2p, no protobuf RPC).
//! Models “subscribed peers receive opaque gossip payloads” as in ethp2p’s
//! [`GossipsubNode.Publish`](https://github.com/ethp2p/ethp2p/blob/main/sim/strategy_gossipsub.go).
//! Gossipsub protobuf `RPC` / control bodies live in `gossipsub_rpc_pb`; this module stays opaque fanout only.

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const FanoutMesh = struct {
    allocator: Allocator,
    /// Topic string (owned key) → subscriber peer ids (each id owned).
    subscriptions: std.StringHashMapUnmanaged(std.ArrayListUnmanaged([]u8)),
    /// Peer id (owned key) → queued gossip blobs (each blob owned).
    inboxes: std.StringHashMapUnmanaged(std.ArrayListUnmanaged([]u8)),

    pub fn init(allocator: Allocator) FanoutMesh {
        return .{
            .allocator = allocator,
            .subscriptions = .{},
            .inboxes = .{},
        };
    }

    pub fn deinit(self: *FanoutMesh) void {
        var sub_it = self.subscriptions.iterator();
        while (sub_it.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
            for (kv.value_ptr.items) |p| self.allocator.free(p);
            kv.value_ptr.deinit(self.allocator);
        }
        self.subscriptions.deinit(self.allocator);

        var in_it = self.inboxes.iterator();
        while (in_it.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
            for (kv.value_ptr.items) |b| self.allocator.free(b);
            kv.value_ptr.deinit(self.allocator);
        }
        self.inboxes.deinit(self.allocator);
    }

    /// Register interest in `topic`. `peer_id` is copied.
    pub fn subscribe(self: *FanoutMesh, peer_id: []const u8, topic: []const u8) Allocator.Error!void {
        const peer_dup = try self.allocator.dupe(u8, peer_id);
        errdefer self.allocator.free(peer_dup);

        const t_gop = try self.subscriptions.getOrPut(self.allocator, topic);
        if (!t_gop.found_existing) {
            t_gop.key_ptr.* = try self.allocator.dupe(u8, topic);
            t_gop.value_ptr.* = .{};
        }

        for (t_gop.value_ptr.items) |p| {
            if (std.mem.eql(u8, p, peer_dup)) {
                self.allocator.free(peer_dup);
                return;
            }
        }
        try t_gop.value_ptr.append(self.allocator, peer_dup);
    }

    /// Deliver a copy of `data` to every subscriber of `topic` except `from` (e.g. publisher peer id).
    pub fn publishData(self: *FanoutMesh, from: []const u8, topic: []const u8, data: []const u8) Allocator.Error!void {
        const subs = self.subscriptions.get(topic) orelse return;
        for (subs.items) |peer| {
            if (std.mem.eql(u8, peer, from)) continue;
            const blob = try self.allocator.dupe(u8, data);
            errdefer self.allocator.free(blob);

            const i_gop = try self.inboxes.getOrPut(self.allocator, peer);
            if (!i_gop.found_existing) {
                i_gop.key_ptr.* = try self.allocator.dupe(u8, peer);
                i_gop.value_ptr.* = .{};
            }
            try i_gop.value_ptr.append(self.allocator, blob);
        }
    }

    /// Moves all queued blobs for `peer_id` into `out`. Caller frees each `[]u8` and clears `out` when done.
    pub fn drainPeer(self: *FanoutMesh, peer_id: []const u8, out: *std.ArrayListUnmanaged([]u8)) Allocator.Error!void {
        const ent = self.inboxes.fetchRemove(peer_id) orelse return;
        defer self.allocator.free(ent.key);
        var list = ent.value;
        defer list.deinit(self.allocator);
        try out.appendSlice(self.allocator, list.items);
    }
};

test "fanout delivers to subscribers except publisher" {
    const gpa = std.testing.allocator;
    var mesh = FanoutMesh.init(gpa);
    defer mesh.deinit();

    const topic = "broadcast-test";
    try mesh.subscribe("alice", topic);
    try mesh.subscribe("bob", topic);

    try mesh.publishData("alice", topic, "hello");

    var bob_inbox: std.ArrayListUnmanaged([]u8) = .{};
    defer {
        for (bob_inbox.items) |s| gpa.free(s);
        bob_inbox.deinit(gpa);
    }
    try mesh.drainPeer("bob", &bob_inbox);
    try std.testing.expectEqual(@as(usize, 1), bob_inbox.items.len);
    try std.testing.expectEqualStrings("hello", bob_inbox.items[0]);

    var alice_inbox: std.ArrayListUnmanaged([]u8) = .{};
    defer alice_inbox.deinit(gpa);
    try mesh.drainPeer("alice", &alice_inbox);
    try std.testing.expectEqual(@as(usize, 0), alice_inbox.items.len);
}
