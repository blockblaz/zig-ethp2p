//! Scenario stats collector, aligned with ethp2p
//! [`sim/collector.go`](https://github.com/ethp2p/ethp2p/blob/main/sim/collector.go).
//!
//! Ports `NodeEvent`, `BandwidthEvent`, `ChunkStats`, `ScenarioStats`, and the
//! `StatsCollector` aggregation (publish/receive correlation → per-node,
//! per-message delivery + latency, plus transport-byte totals and chunk-verdict
//! tallies). The Go collector runs a goroutine draining channels; the Zig sim is
//! synchronous, so `StatsCollector` exposes `record*` methods called directly
//! (the `context.Context` + channel `Run` loop and the slog `LogCollector` have
//! no Zig equivalent — the goroutine/logging carve-out from `UPSTREAM.md`).
//!
//! `time.Time` becomes an `at_us` timestamp (microseconds) supplied by the
//! caller, matching how the Zig sim already threads time elsewhere.

const std = @import("std");
const broadcast_types = @import("../layer/broadcast_types.zig");

const Allocator = std.mem.Allocator;
pub const Verdict = broadcast_types.Verdict;

/// A publish or receive event from a node (Go `NodeEvent`).
pub const NodeEvent = struct {
    message_id: []const u8,
    data: []const u8,
    node_num: usize,
    at_us: i64,
};

/// A periodic bandwidth sample from a node (Go `BandwidthEvent`).
pub const BandwidthEvent = struct {
    node_num: usize,
    sent_bps: i64 = 0,
    received_bps: i64 = 0,
    sent_bytes_total: i64 = 0,
    received_bytes_total: i64 = 0,
    at_us: i64 = 0,
};

/// Chunk-reception verdict tallies for one node (Go `ChunkStats`).
pub const ChunkStats = struct {
    accepted: usize = 0,
    redundant: usize = 0,
    decoding: usize = 0,
    surplus: usize = 0,
};

const BytesMap = std.StringHashMapUnmanaged([]u8);
const TimeMap = std.StringHashMapUnmanaged(i64);
const NodeBytesMap = std.AutoHashMapUnmanaged(usize, BytesMap);
const NodeTimeMap = std.AutoHashMapUnmanaged(usize, TimeMap);
const NodeIntMap = std.AutoHashMapUnmanaged(usize, i64);

/// Collected publish/receive data from a simulation run (Go `ScenarioStats`).
/// Owns all keys and payload copies; free with `deinit`.
pub const ScenarioStats = struct {
    allocator: Allocator,

    published_messages: BytesMap = .empty,
    published_at: TimeMap = .empty,

    received_messages: NodeBytesMap = .empty, // node → message_id → data
    received_at: NodeTimeMap = .empty, // node → message_id → at_us
    received_latency: NodeTimeMap = .empty, // node → message_id → (at - published_at)

    origin_bytes_sent: NodeIntMap = .empty,
    relay_bytes_sent: NodeIntMap = .empty,
    transport_bytes_sent: NodeIntMap = .empty,
    transport_bytes_received: NodeIntMap = .empty,

    chunks_per_node: std.AutoHashMapUnmanaged(usize, ChunkStats) = .empty,

    pub fn init(allocator: Allocator) ScenarioStats {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ScenarioStats) void {
        const a = self.allocator;
        freeBytesMap(a, &self.published_messages);
        freeTimeMap(a, &self.published_at);
        freeNodeBytesMap(a, &self.received_messages);
        freeNodeTimeMap(a, &self.received_at);
        freeNodeTimeMap(a, &self.received_latency);
        self.origin_bytes_sent.deinit(a);
        self.relay_bytes_sent.deinit(a);
        self.transport_bytes_sent.deinit(a);
        self.transport_bytes_received.deinit(a);
        self.chunks_per_node.deinit(a);
        self.* = undefined;
    }
};

/// Aggregates `NodeEvent`/`BandwidthEvent`s into a `ScenarioStats` (Go
/// `StatsCollector`, minus the channel/goroutine `Run` loop).
pub const StatsCollector = struct {
    stats: ScenarioStats,

    pub fn init(allocator: Allocator) StatsCollector {
        return .{ .stats = ScenarioStats.init(allocator) };
    }

    pub fn deinit(self: *StatsCollector) void {
        self.stats.deinit();
    }

    /// Record a publish (Go: `stats.PublishedMessages/PublishedAt`).
    pub fn recordPublished(self: *StatsCollector, ev: NodeEvent) Allocator.Error!void {
        const a = self.stats.allocator;
        try putBytes(a, &self.stats.published_messages, ev.message_id, ev.data);
        try putTime(a, &self.stats.published_at, ev.message_id, ev.at_us);
    }

    /// Record a receive, correlating latency against the publish time when known
    /// (Go: `stats.ReceivedMessages/ReceivedAt/ReceivedLatency`).
    pub fn recordReceived(self: *StatsCollector, ev: NodeEvent) Allocator.Error!void {
        const a = self.stats.allocator;

        const msgs = try nodeBytesEntry(a, &self.stats.received_messages, ev.node_num);
        try putBytes(a, msgs, ev.message_id, ev.data);

        const ats = try nodeTimeEntry(a, &self.stats.received_at, ev.node_num);
        try putTime(a, ats, ev.message_id, ev.at_us);

        if (self.stats.published_at.get(ev.message_id)) |pub_at| {
            const lats = try nodeTimeEntry(a, &self.stats.received_latency, ev.node_num);
            try putTime(a, lats, ev.message_id, ev.at_us - pub_at);
        }
    }

    /// Record a bandwidth sample: transport totals for the node take the sample's
    /// running totals (Go `BandwidthEvent` → `TransportBytesSent/Received`).
    pub fn recordBandwidth(self: *StatsCollector, ev: BandwidthEvent) Allocator.Error!void {
        const a = self.stats.allocator;
        try self.stats.transport_bytes_sent.put(a, ev.node_num, ev.sent_bytes_total);
        try self.stats.transport_bytes_received.put(a, ev.node_num, ev.received_bytes_total);
    }

    /// Add `n` bytes sent by `node` as an origin session (Go `OriginBytesSent`).
    pub fn addOriginBytes(self: *StatsCollector, node: usize, n: i64) Allocator.Error!void {
        try addInt(self.stats.allocator, &self.stats.origin_bytes_sent, node, n);
    }

    /// Add `n` bytes sent by `node` as a relay session (Go `RelayBytesSent`).
    pub fn addRelayBytes(self: *StatsCollector, node: usize, n: i64) Allocator.Error!void {
        try addInt(self.stats.allocator, &self.stats.relay_bytes_sent, node, n);
    }

    /// Tally one chunk-reception verdict for `node` (Go `ChunksPerNode`).
    pub fn recordChunkVerdict(self: *StatsCollector, node: usize, verdict: Verdict) Allocator.Error!void {
        const gop = try self.stats.chunks_per_node.getOrPut(self.stats.allocator, node);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        switch (verdict) {
            .accepted => gop.value_ptr.accepted += 1,
            .redundant => gop.value_ptr.redundant += 1,
            .decoding => gop.value_ptr.decoding += 1,
            .surplus => gop.value_ptr.surplus += 1,
            .invalid, .pending => {},
        }
    }
};

// --- map helpers ------------------------------------------------------------

fn putBytes(a: Allocator, m: *BytesMap, key: []const u8, value: []const u8) Allocator.Error!void {
    const gop = try m.getOrPut(a, key);
    if (gop.found_existing) {
        a.free(gop.value_ptr.*);
    } else {
        gop.key_ptr.* = try a.dupe(u8, key);
    }
    gop.value_ptr.* = try a.dupe(u8, value);
}

fn putTime(a: Allocator, m: *TimeMap, key: []const u8, value: i64) Allocator.Error!void {
    const gop = try m.getOrPut(a, key);
    if (!gop.found_existing) gop.key_ptr.* = try a.dupe(u8, key);
    gop.value_ptr.* = value;
}

fn addInt(a: Allocator, m: *NodeIntMap, node: usize, n: i64) Allocator.Error!void {
    const gop = try m.getOrPut(a, node);
    if (!gop.found_existing) gop.value_ptr.* = 0;
    gop.value_ptr.* += n;
}

fn nodeBytesEntry(a: Allocator, m: *NodeBytesMap, node: usize) Allocator.Error!*BytesMap {
    const gop = try m.getOrPut(a, node);
    if (!gop.found_existing) gop.value_ptr.* = .empty;
    return gop.value_ptr;
}

fn nodeTimeEntry(a: Allocator, m: *NodeTimeMap, node: usize) Allocator.Error!*TimeMap {
    const gop = try m.getOrPut(a, node);
    if (!gop.found_existing) gop.value_ptr.* = .empty;
    return gop.value_ptr;
}

fn freeBytesMap(a: Allocator, m: *BytesMap) void {
    var it = m.iterator();
    while (it.next()) |kv| {
        a.free(kv.key_ptr.*);
        a.free(kv.value_ptr.*);
    }
    m.deinit(a);
}

fn freeTimeMap(a: Allocator, m: *TimeMap) void {
    var it = m.keyIterator();
    while (it.next()) |k| a.free(k.*);
    m.deinit(a);
}

fn freeNodeBytesMap(a: Allocator, m: *NodeBytesMap) void {
    var it = m.valueIterator();
    while (it.next()) |inner| freeBytesMap(a, inner);
    m.deinit(a);
}

fn freeNodeTimeMap(a: Allocator, m: *NodeTimeMap) void {
    var it = m.valueIterator();
    while (it.next()) |inner| freeTimeMap(a, inner);
    m.deinit(a);
}

// --- tests ------------------------------------------------------------------

const testing = std.testing;

test "publish then receive records delivery and latency" {
    var c = StatsCollector.init(testing.allocator);
    defer c.deinit();

    try c.recordPublished(.{ .message_id = "m1", .data = "hello", .node_num = 0, .at_us = 1000 });
    try c.recordReceived(.{ .message_id = "m1", .data = "hello", .node_num = 1, .at_us = 1500 });
    try c.recordReceived(.{ .message_id = "m1", .data = "hello", .node_num = 2, .at_us = 1800 });

    const s = &c.stats;
    try testing.expectEqualStrings("hello", s.published_messages.get("m1").?);
    try testing.expectEqual(@as(i64, 1000), s.published_at.get("m1").?);

    try testing.expectEqualStrings("hello", s.received_messages.get(1).?.get("m1").?);
    try testing.expectEqual(@as(i64, 1500), s.received_at.get(1).?.get("m1").?);
    try testing.expectEqual(@as(i64, 500), s.received_latency.get(1).?.get("m1").?);
    try testing.expectEqual(@as(i64, 800), s.received_latency.get(2).?.get("m1").?);
}

test "receive before publish has no latency entry" {
    var c = StatsCollector.init(testing.allocator);
    defer c.deinit();

    try c.recordReceived(.{ .message_id = "m9", .data = "x", .node_num = 3, .at_us = 200 });

    try testing.expect(c.stats.received_messages.get(3).?.get("m9") != null);
    try testing.expect(c.stats.received_latency.get(3) == null);
}

test "duplicate receive overwrites payload without leaking" {
    var c = StatsCollector.init(testing.allocator);
    defer c.deinit();

    try c.recordPublished(.{ .message_id = "m", .data = "a", .node_num = 0, .at_us = 0 });
    try c.recordReceived(.{ .message_id = "m", .data = "first", .node_num = 1, .at_us = 10 });
    try c.recordReceived(.{ .message_id = "m", .data = "second", .node_num = 1, .at_us = 20 });

    try testing.expectEqualStrings("second", c.stats.received_messages.get(1).?.get("m").?);
    try testing.expectEqual(@as(i64, 20), c.stats.received_latency.get(1).?.get("m").?);
}

test "bandwidth, origin/relay bytes, and chunk verdicts aggregate" {
    var c = StatsCollector.init(testing.allocator);
    defer c.deinit();

    try c.recordBandwidth(.{ .node_num = 0, .sent_bytes_total = 4096, .received_bytes_total = 8192 });
    try c.addOriginBytes(0, 1000);
    try c.addOriginBytes(0, 500);
    try c.addRelayBytes(1, 250);
    try c.recordChunkVerdict(0, .accepted);
    try c.recordChunkVerdict(0, .accepted);
    try c.recordChunkVerdict(0, .redundant);
    try c.recordChunkVerdict(0, .invalid); // not tallied by ChunkStats

    try testing.expectEqual(@as(i64, 4096), c.stats.transport_bytes_sent.get(0).?);
    try testing.expectEqual(@as(i64, 8192), c.stats.transport_bytes_received.get(0).?);
    try testing.expectEqual(@as(i64, 1500), c.stats.origin_bytes_sent.get(0).?);
    try testing.expectEqual(@as(i64, 250), c.stats.relay_bytes_sent.get(1).?);

    const cs = c.stats.chunks_per_node.get(0).?;
    try testing.expectEqual(@as(usize, 2), cs.accepted);
    try testing.expectEqual(@as(usize, 1), cs.redundant);
    try testing.expectEqual(@as(usize, 0), cs.surplus);
}
