//! discv5 Kademlia routing table.
//!
//! 256 buckets keyed by log2-distance from the local node ID.
//! Each bucket holds up to `k` entries, ordered from least-recently-seen
//! (head) to most-recently-seen (tail), matching the discv5 spec.
//!
//! Reference: discv5 spec §5.1 "Node Table".

const std = @import("std");
const crypto = @import("crypto.zig");
const standard = @import("../enr/standard.zig");

pub const NodeId = standard.NodeId;

/// Bucket size — maximum entries per log-distance bucket (discv5 default).
pub const k: usize = 16;

/// Total number of buckets (one per bit of NodeId).
pub const num_buckets: usize = 256;

/// Maximum total entries across all buckets.
pub const max_entries: usize = k * num_buckets;

/// A single entry in a routing bucket.
pub const Entry = struct {
    node_id: NodeId,
    /// Compressed secp256k1 public key of the remote node.
    pubkey: [crypto.pubkey_len]u8 = [_]u8{0} ** crypto.pubkey_len,
    /// UDP address used for discv5 communication.
    udp_addr: std.net.Address,
    /// ENR sequence number of the last-seen record.
    enr_seq: u64,
    /// Monotonic timestamp of last successful interaction (ns).
    last_seen_ns: u64,
};

/// A single routing bucket (k-bucket).
pub const Bucket = struct {
    entries: [k]Entry = undefined,
    len: usize = 0,

    /// Add or refresh `entry`. Returns true if the entry was inserted or
    /// updated; false if the bucket is full and the entry was not inserted
    /// (caller should ping the least-recently-seen entry instead).
    pub fn addOrRefresh(self: *Bucket, entry: Entry) bool {
        // Check if already present — update and move to tail.
        for (self.entries[0..self.len], 0..) |*e, i| {
            if (std.mem.eql(u8, &e.node_id, &entry.node_id)) {
                e.* = entry;
                // Rotate to tail (most-recently-seen).
                const saved = self.entries[i];
                std.mem.copyBackwards(Entry, self.entries[i .. self.len - 1], self.entries[i + 1 .. self.len]);
                self.entries[self.len - 1] = saved;
                return true;
            }
        }

        if (self.len < k) {
            self.entries[self.len] = entry;
            self.len += 1;
            return true;
        }

        return false; // Bucket full; caller pings entries[0] (LRS).
    }

    /// Remove an entry by node ID.
    pub fn remove(self: *Bucket, node_id: NodeId) bool {
        for (self.entries[0..self.len], 0..) |e, i| {
            if (std.mem.eql(u8, &e.node_id, &node_id)) {
                std.mem.copyForwards(Entry, self.entries[i .. self.len - 1], self.entries[i + 1 .. self.len]);
                self.len -= 1;
                return true;
            }
        }
        return false;
    }

    pub fn isFull(self: *const Bucket) bool {
        return self.len == k;
    }

    pub fn leastRecentlySeen(self: *const Bucket) ?*const Entry {
        if (self.len == 0) return null;
        return &self.entries[0];
    }
};

/// The full 256-bucket routing table.
pub const RoutingTable = struct {
    local_id: NodeId,
    buckets: [num_buckets]Bucket = [_]Bucket{.{}} ** num_buckets,

    pub fn init(local_id: NodeId) RoutingTable {
        return .{ .local_id = local_id };
    }

    /// XOR distance between two NodeIds.  Returns 256 bits as a [32]u8.
    pub fn distance(a: NodeId, b: NodeId) NodeId {
        var d: NodeId = undefined;
        for (&d, a, b) |*di, ai, bi| di.* = ai ^ bi;
        return d;
    }

    /// log2-distance bucket index (0–255).  Returns null for identical IDs.
    pub fn bucketIndex(a: NodeId, b: NodeId) ?usize {
        const d = distance(a, b);
        // Find the highest set bit in d (big-endian).
        for (d, 0..) |byte, i| {
            if (byte != 0) {
                const bit: usize = 7 - @ctz(@bitReverse(byte));
                return (31 - i) * 8 + bit;
            }
        }
        return null; // Same node.
    }

    /// Insert or refresh a node. Returns false if the bucket is full.
    pub fn add(self: *RoutingTable, entry: Entry) bool {
        const idx = bucketIndex(self.local_id, entry.node_id) orelse return false;
        return self.buckets[idx].addOrRefresh(entry);
    }

    /// Remove a node from the table.
    pub fn remove(self: *RoutingTable, node_id: NodeId) bool {
        const idx = bucketIndex(self.local_id, node_id) orelse return false;
        return self.buckets[idx].remove(node_id);
    }

    /// Find the `n` closest nodes to `target` (by XOR distance).
    /// Writes at most `n` entries into `out`; returns the count written.
    pub fn closest(self: *const RoutingTable, target: NodeId, out: []Entry) usize {
        var count: usize = 0;
        // Gather all entries.
        var all: [max_entries]Entry = undefined;
        var total: usize = 0;
        for (&self.buckets) |*b| {
            for (b.entries[0..b.len]) |e| {
                all[total] = e;
                total += 1;
            }
        }
        // Sort by XOR distance to target.
        const Ctx = struct {
            target: NodeId,
            pub fn lessThan(ctx: @This(), a: Entry, b_entry: Entry) bool {
                const da = distance(ctx.target, a.node_id);
                const db = distance(ctx.target, b_entry.node_id);
                return std.mem.lessThan(u8, &da, &db);
            }
        };
        std.sort.pdq(Entry, all[0..total], Ctx{ .target = target }, Ctx.lessThan);
        count = @min(out.len, total);
        @memcpy(out[0..count], all[0..count]);
        return count;
    }

    /// Total live entries across all buckets.
    pub fn totalEntries(self: *const RoutingTable) usize {
        var n: usize = 0;
        for (&self.buckets) |*b| n += b.len;
        return n;
    }

    /// Look up a specific node by ID.  Returns null if not in the table.
    pub fn getEntry(self: *const RoutingTable, node_id: NodeId) ?Entry {
        const idx = bucketIndex(self.local_id, node_id) orelse return null;
        const b = &self.buckets[idx];
        for (b.entries[0..b.len]) |e| {
            if (std.mem.eql(u8, &e.node_id, &node_id)) return e;
        }
        return null;
    }

    /// Update `last_seen_ns` for an existing entry (no-op if not found).
    pub fn refreshNode(self: *RoutingTable, node_id: NodeId, now_ns: u64) void {
        const idx = bucketIndex(self.local_id, node_id) orelse return;
        const b = &self.buckets[idx];
        for (b.entries[0..b.len]) |*e| {
            if (std.mem.eql(u8, &e.node_id, &node_id)) {
                e.last_seen_ns = now_ns;
                return;
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn makeId(seed: u8) NodeId {
    var id: NodeId = [_]u8{0} ** 32;
    id[31] = seed;
    return id;
}

test "bucketIndex returns null for identical IDs" {
    const id = makeId(0xAB);
    try std.testing.expect(RoutingTable.bucketIndex(id, id) == null);
}

test "bucketIndex is symmetric" {
    const a = makeId(1);
    const b = makeId(2);
    try std.testing.expectEqual(RoutingTable.bucketIndex(a, b), RoutingTable.bucketIndex(b, a));
}

test "bucket addOrRefresh fills up to k then rejects" {
    var bucket = Bucket{};
    for (0..k) |i| {
        const entry = Entry{
            .node_id = makeId(@intCast(i + 1)),
            .udp_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9000),
            .enr_seq = 1,
            .last_seen_ns = 0,
        };
        try std.testing.expect(bucket.addOrRefresh(entry));
    }
    try std.testing.expect(bucket.isFull());
    const extra = Entry{
        .node_id = makeId(0xff),
        .udp_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9000),
        .enr_seq = 1,
        .last_seen_ns = 0,
    };
    try std.testing.expect(!bucket.addOrRefresh(extra));
}

test "routing table add and closest" {
    const local = makeId(0);
    var table = RoutingTable.init(local);

    for (1..10) |i| {
        try std.testing.expect(table.add(.{
            .node_id = makeId(@intCast(i)),
            .udp_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, @intCast(9000 + i)),
            .enr_seq = 1,
            .last_seen_ns = 0,
        }));
    }

    try std.testing.expectEqual(@as(usize, 9), table.totalEntries());

    var out: [3]Entry = undefined;
    const n = table.closest(makeId(1), &out);
    try std.testing.expectEqual(@as(usize, 3), n);
    // Closest to 0x01 should itself be 0x01.
    try std.testing.expectEqual(makeId(1), out[0].node_id);
}

test "remove decrements total" {
    const local = makeId(0);
    var table = RoutingTable.init(local);
    _ = table.add(.{
        .node_id = makeId(5),
        .udp_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9005),
        .enr_seq = 1,
        .last_seen_ns = 0,
    });
    try std.testing.expectEqual(@as(usize, 1), table.totalEntries());
    try std.testing.expect(table.remove(makeId(5)));
    try std.testing.expectEqual(@as(usize, 0), table.totalEntries());
}
