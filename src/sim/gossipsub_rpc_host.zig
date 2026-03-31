//! In-process duplex link for length-prefixed gossipsub `RPC` frames (unsigned varint length +
//! protobuf body), similar in spirit to a simnet-style stream between two peers without TCP or QUIC.
//!
//! Use `Link` for tests and drivers; production stacks still need a real libp2p transport.

const std = @import("std");
const rpc_pb = @import("gossipsub_rpc_pb.zig");

const Allocator = std.mem.Allocator;

pub const RecvError = error{BadRpcFrame};

pub const Link = struct {
    ab: std.ArrayListUnmanaged(u8),
    ba: std.ArrayListUnmanaged(u8),
    gpa: Allocator,

    pub fn init(gpa: Allocator) Link {
        return .{ .ab = .{}, .ba = .{}, .gpa = gpa };
    }

    pub fn deinit(self: *Link) void {
        self.ab.deinit(self.gpa);
        self.ba.deinit(self.gpa);
    }

    pub fn endpointA(self: *Link) Endpoint {
        return .{ .outbound = &self.ab, .inbound = &self.ba, .gpa = self.gpa };
    }

    pub fn endpointB(self: *Link) Endpoint {
        return .{ .outbound = &self.ba, .inbound = &self.ab, .gpa = self.gpa };
    }
};

pub const Endpoint = struct {
    outbound: *std.ArrayListUnmanaged(u8),
    inbound: *std.ArrayListUnmanaged(u8),
    gpa: Allocator,

    /// Appends one varint-length-prefixed `RPC` to the peer's inbound buffer.
    pub fn sendRpc(self: *Endpoint, r: rpc_pb.RpcEncodeRef) Allocator.Error!void {
        const body = try rpc_pb.encodeRpc(self.gpa, r);
        defer self.gpa.free(body);
        const framed = try rpc_pb.encodeRpcLengthPrefixed(self.gpa, body);
        defer self.gpa.free(framed);
        try self.outbound.appendSlice(self.gpa, framed);
    }

    /// Removes and decodes the first full frame from `inbound`, if present.
    /// Returns `null` when `inbound` is empty or holds an incomplete frame (`Truncated` length parse).
    pub fn recvRpcOwned(self: *Endpoint, allocator: Allocator) (RecvError || Allocator.Error)!?rpc_pb.RpcOwned {
        if (self.inbound.items.len == 0) return null;
        const pr = rpc_pb.decodeRpcLengthPrefixedPrefix(self.inbound.items) catch |e| switch (e) {
            error.Truncated => return null,
            else => return error.BadRpcFrame,
        };
        var out = rpc_pb.decodeRpcOwned(allocator, pr.rpc) catch return error.BadRpcFrame;
        errdefer out.deinit(allocator);
        const consumed = self.inbound.items.len - pr.rest.len;
        try self.inbound.replaceRange(self.gpa, 0, consumed, &[_]u8{});
        return out;
    }
};

test "duplex A sends subscribe B receives" {
    const gpa = std.testing.allocator;
    var link = Link.init(gpa);
    defer link.deinit();

    var a = link.endpointA();
    var b = link.endpointB();

    try a.sendRpc(.{ .subscriptions = &.{.{ .subscribe = true, .topicid = "mesh/x" }} });

    const got_opt = try b.recvRpcOwned(gpa);
    try std.testing.expect(got_opt != null);
    var got = got_opt.?;
    defer got.deinit(gpa);

    try std.testing.expectEqual(@as(usize, 1), got.subscriptions.len);
    try std.testing.expect(got.subscriptions[0].subscribe.?);
    try std.testing.expectEqualStrings("mesh/x", got.subscriptions[0].topicid.?);

    try std.testing.expect((try b.recvRpcOwned(gpa)) == null);
}

test "duplex round trip control and partial" {
    const gpa = std.testing.allocator;
    var link = Link.init(gpa);
    defer link.deinit();

    var a = link.endpointA();
    var b = link.endpointB();

    const ih = try rpc_pb.encodeIHave(gpa, "t", &.{"m"});
    defer gpa.free(ih);
    const ctl = try rpc_pb.encodeControlMessage(gpa, .{ .ihave = &.{ih} });
    defer gpa.free(ctl);
    const pext = try rpc_pb.encodePartialMessagesExtension(gpa, .{ .topic_id = "tp" });
    defer gpa.free(pext);

    try b.sendRpc(.{
        .control = ctl,
        .partial = pext,
    });

    const got_opt = try a.recvRpcOwned(gpa);
    try std.testing.expect(got_opt != null);
    var got = got_opt.?;
    defer got.deinit(gpa);

    try std.testing.expect(got.control != null);
    try std.testing.expect(got.partial != null);
    var pm = try rpc_pb.decodePartialMessagesExtensionOwned(gpa, got.partial.?);
    defer pm.deinit(gpa);
    try std.testing.expectEqualStrings("tp", pm.topic_id.?);
}
