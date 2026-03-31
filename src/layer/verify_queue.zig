//! Single-threaded FIFO for post-verify results (shim for Go `Strategy.Verified()` / channel delivery).

const std = @import("std");
const broadcast_types = @import("broadcast_types.zig");

const Allocator = std.mem.Allocator;

pub const VerifyRecord = struct {
    handle: broadcast_types.ChunkHandle,
    verdict: broadcast_types.Verdict,
};

pub const VerifyQueue = struct {
    items: std.ArrayListUnmanaged(VerifyRecord) = .{},

    pub fn deinit(self: *VerifyQueue, allocator: Allocator) void {
        self.items.deinit(allocator);
    }

    pub fn push(self: *VerifyQueue, allocator: Allocator, rec: VerifyRecord) Allocator.Error!void {
        try self.items.append(allocator, rec);
    }

    pub fn popFront(self: *VerifyQueue) ?VerifyRecord {
        if (self.items.items.len == 0) return null;
        return self.items.orderedRemove(0);
    }
};

test "verify queue fifo" {
    const gpa = std.testing.allocator;
    var q: VerifyQueue = .{};
    defer q.deinit(gpa);

    try q.push(gpa, .{ .handle = 1, .verdict = .accepted });
    try q.push(gpa, .{ .handle = 2, .verdict = .invalid });

    try std.testing.expectEqual(@as(broadcast_types.ChunkHandle, 1), q.popFront().?.handle);
    try std.testing.expectEqual(broadcast_types.Verdict.invalid, q.popFront().?.verdict);
    try std.testing.expect(q.popFront() == null);
}
