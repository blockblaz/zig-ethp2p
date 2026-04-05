//! Connection pool: hot / warm / cold warmth states.
//!
//! Mirrors the three-tier connection pool described in the ethp2p spec §Peering:
//!   hot  — QUIC session established, ready for immediate stream open.
//!   warm — 0-RTT session ticket cached; first stream costs ~0 RTT.
//!   cold — no session; full TLS 1.3 handshake required.
//!
//! Pool capacity comes from duty.zig tier constants.

const std = @import("std");
const duty_mod = @import("duty.zig");
const discv5_table = @import("../discv5/table.zig");

pub const NodeId = discv5_table.NodeId;

pub const Warmth = enum { hot, warm, cold };

pub const PoolEntry = struct {
    node_id: NodeId,
    warmth: Warmth = .cold,
    /// Monotonic timestamp when this entry was last promoted (ns).
    promoted_ns: u64 = 0,
    /// 0-RTT session ticket (opaque bytes; null for cold entries).
    session_ticket: ?[]u8 = null,
};

pub const Pool = struct {
    allocator: std.mem.Allocator,
    entries: std.AutoHashMapUnmanaged(NodeId, PoolEntry) = .{},

    pub fn init(allocator: std.mem.Allocator) Pool {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Pool) void {
        var it = self.entries.valueIterator();
        while (it.next()) |e| {
            if (e.session_ticket) |t| self.allocator.free(t);
        }
        self.entries.deinit(self.allocator);
    }

    /// Promote a peer to `hot` (session just established).
    pub fn promoteHot(self: *Pool, node_id: NodeId, now_ns: u64) std.mem.Allocator.Error!void {
        const gop = try self.entries.getOrPut(self.allocator, node_id);
        gop.value_ptr.* = .{ .node_id = node_id, .warmth = .hot, .promoted_ns = now_ns };
    }

    /// Cache a 0-RTT session ticket (promotes to `warm`).
    pub fn promoteWarm(
        self: *Pool,
        node_id: NodeId,
        ticket: []const u8,
        now_ns: u64,
    ) std.mem.Allocator.Error!void {
        const gop = try self.entries.getOrPut(self.allocator, node_id);
        const old_ticket = if (gop.found_existing) gop.value_ptr.session_ticket else null;
        if (old_ticket) |t| self.allocator.free(t);
        gop.value_ptr.* = .{
            .node_id = node_id,
            .warmth = .warm,
            .promoted_ns = now_ns,
            .session_ticket = try self.allocator.dupe(u8, ticket),
        };
    }

    /// Demote to `cold` (session closed or evicted).
    pub fn demote(self: *Pool, node_id: NodeId) void {
        if (self.entries.getPtr(node_id)) |e| {
            if (e.session_ticket) |t| {
                self.allocator.free(t);
                e.session_ticket = null;
            }
            e.warmth = .cold;
        }
    }

    pub fn get(self: *Pool, node_id: NodeId) ?*PoolEntry {
        return self.entries.getPtr(node_id);
    }

    pub fn warmth(self: *Pool, node_id: NodeId) Warmth {
        return if (self.entries.getPtr(node_id)) |e| e.warmth else .cold;
    }

    pub fn count(self: *const Pool) usize {
        return self.entries.count();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "pool warmth transitions" {
    const gpa = std.testing.allocator;
    var pool = Pool.init(gpa);
    defer pool.deinit();

    const id = [_]u8{0xAA} ** 32;

    try std.testing.expectEqual(Warmth.cold, pool.warmth(id));

    try pool.promoteWarm(id, "ticket-bytes", 1_000);
    try std.testing.expectEqual(Warmth.warm, pool.warmth(id));
    try std.testing.expect(pool.get(id).?.session_ticket != null);

    try pool.promoteHot(id, 2_000);
    try std.testing.expectEqual(Warmth.hot, pool.warmth(id));

    pool.demote(id);
    try std.testing.expectEqual(Warmth.cold, pool.warmth(id));
}

test "pool count" {
    const gpa = std.testing.allocator;
    var pool = Pool.init(gpa);
    defer pool.deinit();

    try pool.promoteHot([_]u8{1} ** 32, 0);
    try pool.promoteHot([_]u8{2} ** 32, 0);
    try std.testing.expectEqual(@as(usize, 2), pool.count());
}
