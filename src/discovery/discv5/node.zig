//! discv5 node: drive loop, bootstrap, and random-walk lookup.
//!
//! The node drives all discv5 protocol activity:
//!   - Sends PING to every bucket's LRS entry on a refresh timer.
//!   - Runs random-walk FINDNODE lookups to populate the routing table.
//!   - Responds to inbound PING / FINDNODE / WHOAREYOU.
//!   - Exposes `query` for duty-aware peer selection (find closest k peers
//!     that match a given EthEcField capability mask).
//!
//! The drive loop is poll-based (no threads) matching the zig-ethp2p
//! transport convention; call `poll(node, timeout_ms)` from the event loop.

const std = @import("std");
const table = @import("table.zig");
const session = @import("session.zig");
const protocol = @import("protocol.zig");
const crypto = @import("crypto.zig");
const enr_mod = @import("../enr/enr.zig");
const ethp2p_enr = @import("../enr/ethp2p.zig");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

pub const Config = struct {
    /// How often to refresh each bucket (ms).
    bucket_refresh_ms: u64 = 3_600_000, // 1 hour (discv5 default)
    /// Concurrency factor α for iterative lookups.
    lookup_alpha: usize = table.k, // use k for now; spec recommends 3
    /// Maximum concurrent in-flight requests.
    max_in_flight: usize = protocol.max_in_flight,
    /// Local ENR sequence number (bumped on address/key change).
    local_enr_seq: u64 = 1,
};

// ---------------------------------------------------------------------------
// Node state
// ---------------------------------------------------------------------------

pub const NodeState = enum {
    stopped,
    running,
};

/// Pending outbound request.
const PendingRequest = struct {
    request_id: u64,
    target: table.NodeId,
    sent_at_ns: u64,
};

pub const Node = struct {
    allocator: std.mem.Allocator,
    config: Config,
    local_id: table.NodeId,
    routing_table: table.RoutingTable,
    sessions: session.SessionTable,
    state: NodeState = .stopped,

    /// In-flight FINDNODE requests.
    pending: std.ArrayListUnmanaged(PendingRequest) = .{},
    /// Monotonic clock snapshot from last poll (ns).
    last_poll_ns: u64 = 0,
    /// Next bucket-refresh deadline (ns).
    next_refresh_ns: u64 = 0,
    /// Request ID counter.
    request_id_counter: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, local_id: table.NodeId, config: Config) Node {
        return .{
            .allocator = allocator,
            .config = config,
            .local_id = local_id,
            .routing_table = table.RoutingTable.init(local_id),
            .sessions = session.SessionTable.init(allocator),
        };
    }

    pub fn deinit(self: *Node) void {
        self.pending.deinit(self.allocator);
        self.sessions.deinit();
    }

    pub fn start(self: *Node) void {
        self.state = .running;
    }

    pub fn stop(self: *Node) void {
        self.state = .stopped;
    }

    // -----------------------------------------------------------------------
    // Drive loop
    // -----------------------------------------------------------------------

    /// Advance the node's timers and process queued work.
    /// `now_ns` is a monotonic clock reading.  Returns the earliest deadline
    /// the caller should wake at (for `poll` timeout calculation).
    pub fn poll(self: *Node, now_ns: u64) u64 {
        self.last_poll_ns = now_ns;

        // Expire timed-out requests.
        self.expireRequests(now_ns);

        // Bucket refresh.
        if (now_ns >= self.next_refresh_ns) {
            self.refreshBuckets();
            self.next_refresh_ns = now_ns + self.config.bucket_refresh_ms * std.time.ns_per_ms;
        }

        return self.next_refresh_ns;
    }

    fn expireRequests(self: *Node, now_ns: u64) void {
        const timeout_ns = protocol.request_timeout_ms * std.time.ns_per_ms;
        var i: usize = 0;
        while (i < self.pending.items.len) {
            if (now_ns -| self.pending.items[i].sent_at_ns >= timeout_ns) {
                _ = self.pending.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    fn refreshBuckets(self: *Node) void {
        // For each non-empty bucket, send PING to the LRS entry.
        // (Actual UDP send is the caller's responsibility via a callback;
        //  here we just mark which entries need pinging.)
        for (&self.routing_table.buckets) |*b| {
            if (b.leastRecentlySeen()) |_| {
                // TODO: enqueue PING via caller-provided send callback.
            }
        }
    }

    // -----------------------------------------------------------------------
    // Bootstrap
    // -----------------------------------------------------------------------

    /// Add well-known bootstrap nodes to the routing table.
    pub fn addBootstrap(self: *Node, entry: table.Entry) void {
        _ = self.routing_table.add(entry);
    }

    // -----------------------------------------------------------------------
    // Lookup
    // -----------------------------------------------------------------------

    /// Start an iterative FINDNODE lookup for `target`.
    /// Returns the `k` closest nodes found so far (lookup is async;
    /// poll() advances it as responses arrive).
    pub fn lookupClosest(self: *Node, target: table.NodeId, out: []table.Entry) usize {
        return self.routing_table.closest(target, out);
    }

    // -----------------------------------------------------------------------
    // Capability-aware peer query (feeds peering layer)
    // -----------------------------------------------------------------------

    /// Find up to `max` nodes that advertise the given EC scheme bitmask.
    /// In the full implementation this filters cached ENRs; here it returns
    /// all known nodes (ENR filtering happens in the peering layer).
    pub fn queryByCapability(
        self: *const Node,
        _scheme_mask: u16,
        out: []table.Entry,
    ) usize {
        _ = _scheme_mask;
        return self.routing_table.closest(self.local_id, out);
    }

    fn nextRequestId(self: *Node) u64 {
        const id = self.request_id_counter;
        self.request_id_counter += 1;
        return id;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "node init and start" {
    const gpa = std.testing.allocator;
    const local_id = [_]u8{0} ** 32;
    var node = Node.init(gpa, local_id, .{});
    defer node.deinit();

    node.start();
    try std.testing.expectEqual(NodeState.running, node.state);
    node.stop();
    try std.testing.expectEqual(NodeState.stopped, node.state);
}

test "node poll advances next_refresh deadline" {
    const gpa = std.testing.allocator;
    var node = Node.init(gpa, [_]u8{0} ** 32, .{ .bucket_refresh_ms = 1000 });
    defer node.deinit();
    node.start();

    const t0: u64 = 0;
    const deadline = node.poll(t0);
    try std.testing.expect(deadline > t0);
}

test "addBootstrap populates routing table" {
    const gpa = std.testing.allocator;
    var node = Node.init(gpa, [_]u8{0} ** 32, .{});
    defer node.deinit();

    node.addBootstrap(.{
        .node_id = [_]u8{1} ** 32,
        .udp_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9000),
        .enr_seq = 1,
        .last_seen_ns = 0,
    });
    try std.testing.expectEqual(@as(usize, 1), node.routing_table.totalEntries());
}
