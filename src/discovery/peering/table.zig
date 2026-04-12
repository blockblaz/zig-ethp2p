//! Selfish + altruistic peer table.
//!
//! Two segments per the ethp2p spec §Peering:
//!   Selfish   — duty-typed slots; evict lowest-scoring peer when full.
//!   Altruistic — diversity peers for chain sync and bootstrapping.
//!
//! Peers are keyed by NodeId.  Each entry carries its score and the
//! connection pool tier (hot/warm/cold) it currently occupies.

const std = @import("std");
const score_mod = @import("score.zig");
const duty_mod = @import("duty.zig");
const discv5_table = @import("../discv5/table.zig");
const ethp2p_enr = @import("../enr/ethp2p.zig");

pub const NodeId = discv5_table.NodeId;
pub const Score = score_mod.Score;

// ---------------------------------------------------------------------------
// Peer entry
// ---------------------------------------------------------------------------

pub const ConnectionTier = enum { hot, warm, cold };

pub const PeerEntry = struct {
    node_id: NodeId,
    udp_addr: std.net.Address,
    score: Score = .{},
    tier: ConnectionTier = .cold,
    /// Capability field from the peer's ENR.
    eth_ec: ?ethp2p_enr.EthEcField = null,
    /// Duty slot this entry occupies (null = altruistic).
    duty: ?duty_mod.DutyKind = null,
};

// ---------------------------------------------------------------------------
// Selfish segment
// ---------------------------------------------------------------------------

pub const SelfishTable = struct {
    entries: std.ArrayListUnmanaged(PeerEntry) = .{},
    capacity: usize,

    pub fn init(capacity: usize) SelfishTable {
        return .{ .capacity = capacity };
    }

    pub fn deinit(self: *SelfishTable, allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
    }

    /// Insert or update a peer.  If full, evicts the lowest-scoring entry.
    pub fn upsert(
        self: *SelfishTable,
        allocator: std.mem.Allocator,
        entry: PeerEntry,
    ) std.mem.Allocator.Error!void {
        // Update if already present.
        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, &e.node_id, &entry.node_id)) {
                e.* = entry;
                return;
            }
        }

        if (self.entries.items.len >= self.capacity) {
            // Evict the lowest-scoring entry.
            var min_idx: usize = 0;
            var min_score: i32 = std.math.maxInt(i32);
            for (self.entries.items, 0..) |e, i| {
                if (e.score.composite < min_score) {
                    min_score = e.score.composite;
                    min_idx = i;
                }
            }
            if (entry.score.composite <= min_score) return; // New entry worse — skip.
            self.entries.items[min_idx] = entry;
            return;
        }

        try self.entries.append(allocator, entry);
    }

    pub fn remove(self: *SelfishTable, node_id: NodeId) bool {
        for (self.entries.items, 0..) |e, i| {
            if (std.mem.eql(u8, &e.node_id, &node_id)) {
                _ = self.entries.swapRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn get(self: *SelfishTable, node_id: NodeId) ?*PeerEntry {
        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, &e.node_id, &node_id)) return e;
        }
        return null;
    }

    /// Select up to `max` peers for `duty`, filtered by `SelectionReq`.
    pub fn selectForDuty(
        self: *const SelfishTable,
        duty: duty_mod.DutyKind,
        req: duty_mod.SelectionReq,
        out: []NodeId,
    ) usize {
        var count: usize = 0;
        for (self.entries.items) |e| {
            if (e.duty != null and e.duty.? != duty) continue;
            if (req.max_rtt_ms > 0 and e.score.rtt_ms > req.max_rtt_ms) continue;
            if (count >= out.len) break;
            out[count] = e.node_id;
            count += 1;
        }
        return count;
    }

    pub fn len(self: *const SelfishTable) usize {
        return self.entries.items.len;
    }
};

// ---------------------------------------------------------------------------
// Altruistic segment
// ---------------------------------------------------------------------------

pub const AltruisticTable = struct {
    entries: std.ArrayListUnmanaged(PeerEntry) = .{},
    capacity: usize,

    pub fn init(capacity: usize) AltruisticTable {
        return .{ .capacity = capacity };
    }

    pub fn deinit(self: *AltruisticTable, allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
    }

    pub fn upsert(
        self: *AltruisticTable,
        allocator: std.mem.Allocator,
        entry: PeerEntry,
    ) std.mem.Allocator.Error!void {
        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, &e.node_id, &entry.node_id)) {
                e.* = entry;
                return;
            }
        }
        if (self.entries.items.len >= self.capacity) return; // Full; no eviction for altruistic.
        try self.entries.append(allocator, entry);
    }

    pub fn len(self: *const AltruisticTable) usize {
        return self.entries.items.len;
    }
};

// ---------------------------------------------------------------------------
// Combined peer table
// ---------------------------------------------------------------------------

pub const PeerTable = struct {
    allocator: std.mem.Allocator,
    selfish: SelfishTable,
    altruistic: AltruisticTable,

    pub fn init(allocator: std.mem.Allocator) PeerTable {
        return .{
            .allocator = allocator,
            .selfish = SelfishTable.init(duty_mod.total_selfish_slots),
            .altruistic = AltruisticTable.init(duty_mod.altruistic_slots),
        };
    }

    pub fn deinit(self: *PeerTable) void {
        self.selfish.deinit(self.allocator);
        self.altruistic.deinit(self.allocator);
    }

    pub fn upsertSelfish(self: *PeerTable, entry: PeerEntry) std.mem.Allocator.Error!void {
        return self.selfish.upsert(self.allocator, entry);
    }

    pub fn upsertAltruistic(self: *PeerTable, entry: PeerEntry) std.mem.Allocator.Error!void {
        return self.altruistic.upsert(self.allocator, entry);
    }

    pub fn totalPeers(self: *const PeerTable) usize {
        return self.selfish.len() + self.altruistic.len();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn makeId(seed: u8) NodeId {
    return [_]u8{seed} ** 32;
}

fn makeEntry(seed: u8, composite: i32) PeerEntry {
    var e = PeerEntry{
        .node_id = makeId(seed),
        .udp_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9000),
    };
    e.score.composite = composite;
    return e;
}

test "selfish table evicts lowest-score when full" {
    const gpa = std.testing.allocator;
    var t = SelfishTable.init(2);
    defer t.deinit(gpa);

    try t.upsert(gpa, makeEntry(1, 100));
    try t.upsert(gpa, makeEntry(2, 50));
    // Third entry with score 75 should evict the score-50 peer.
    try t.upsert(gpa, makeEntry(3, 75));

    try std.testing.expectEqual(@as(usize, 2), t.len());
    try std.testing.expect(t.get(makeId(2)) == null);
    try std.testing.expect(t.get(makeId(1)) != null);
    try std.testing.expect(t.get(makeId(3)) != null);
}

test "peer table total peers" {
    const gpa = std.testing.allocator;
    var pt = PeerTable.init(gpa);
    defer pt.deinit();

    try pt.upsertSelfish(makeEntry(1, 100));
    try pt.upsertAltruistic(makeEntry(2, 50));
    try std.testing.expectEqual(@as(usize, 2), pt.totalPeers());
}
