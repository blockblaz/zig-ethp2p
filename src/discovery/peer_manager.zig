//! Peer manager: bridges discv5 discovery, QUIC transport, and the peering table.
//!
//! Responsibilities:
//!   1. Queries discv5 for peers advertising the required EC scheme.
//!   2. Schedules proactive QUIC dials via the warmup scheduler.
//!   3. Calls `eth_ec_quic.dial` for each warmed peer.
//!   4. Registers connected peers in the selfish / altruistic `PeerTable`.
//!   5. Evicts peers that fall below the score floor.
//!
//! Usage: construct with references to all three sub-systems, then call
//! `poll(now_ns, slot_offset_ms)` from the owning event loop.

const std = @import("std");
const discv5_node = @import("discv5/node.zig");
const peering_table = @import("peering/table.zig");
const warmup_mod = @import("peering/warmup.zig");
const pool_mod = @import("peering/pool.zig");
const ethp2p_enr = @import("enr/ethp2p.zig");
const duty_mod = @import("peering/duty.zig");
const eth_ec_quic = @import("../transport/eth_ec_quic.zig");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

pub const PeerManagerConfig = struct {
    /// EC scheme bitmask for selfish peer selection (0 = accept any).
    scheme_mask: u16 = ethp2p_enr.scheme_bit_reed_solomon,
    /// How many selfish peers to target.
    target_selfish: usize = duty_mod.total_selfish_slots,
    /// How many altruistic peers to target.
    target_altruistic: usize = duty_mod.altruistic_slots,
    /// QUIC dial config forwarded to eth_ec_quic.dial.
    quic_config: eth_ec_quic.EthEcQuicConfig = eth_ec_quic.EthEcQuicConfig.default(),
};

// ---------------------------------------------------------------------------
// PeerManager
// ---------------------------------------------------------------------------

pub const PeerManager = struct {
    allocator: std.mem.Allocator,
    config: PeerManagerConfig,

    node: *discv5_node.Node,
    peers: *peering_table.PeerTable,
    warmup: *warmup_mod.Scheduler,
    pool: *pool_mod.Pool,

    pub fn init(
        allocator: std.mem.Allocator,
        config: PeerManagerConfig,
        node: *discv5_node.Node,
        peers: *peering_table.PeerTable,
        warmup: *warmup_mod.Scheduler,
        pool: *pool_mod.Pool,
    ) PeerManager {
        return .{
            .allocator = allocator,
            .config = config,
            .node = node,
            .peers = peers,
            .warmup = warmup,
            .pool = pool,
        };
    }

    // -----------------------------------------------------------------------
    // Poll
    // -----------------------------------------------------------------------

    /// Drive discovery → connection warmup → peering table in one tick.
    /// Call from the owning event loop every ~100 ms or on each slot event.
    pub fn poll(self: *PeerManager, now_ns: u64, slot_offset_ms: u64) void {
        _ = self.node.poll(now_ns);
        self.scheduleWarmup(now_ns, slot_offset_ms);
        self.flushWarmup();
        self.evictBelow(duty_mod.score_eviction_floor);
    }

    // -----------------------------------------------------------------------
    // Warmup scheduling
    // -----------------------------------------------------------------------

    /// Query discv5 for capability peers and enqueue warmup requests.
    fn scheduleWarmup(self: *PeerManager, now_ns: u64, slot_offset_ms: u64) void {
        if (warmup_mod.currentPhase(slot_offset_ms) != .idle) return;

        const current_slot = now_ns / (warmup_mod.slot_duration_ms * std.time.ns_per_ms);
        self.warmup.advanceSlot(current_slot);

        // Query discv5 for peers with the required scheme.
        var candidates: [duty_mod.total_selfish_slots * 2]discv5_node.table.Entry = undefined;
        const n = self.node.queryByCapability(self.config.scheme_mask, &candidates);

        // Enqueue warmup for peers not already hot/warm.
        for (candidates[0..n]) |entry| {
            const tier = self.pool.warmth(entry.node_id);
            if (tier == .hot or tier == .warm) continue;

            const req = warmup_mod.WarmupRequest{
                .node_id = entry.node_id,
                .addr = entry.udp_addr,
                .target_slot = current_slot + 1,
            };
            _ = self.warmup.enqueue(req, slot_offset_ms) catch {};
        }
    }

    /// Drain the warmup queue and issue QUIC dials.
    fn flushWarmup(self: *PeerManager) void {
        var reqs: [32]warmup_mod.WarmupRequest = undefined;
        const n = self.warmup.drain(&reqs);
        for (reqs[0..n]) |req| {
            self.dialPeer(req.node_id, req.addr);
        }
    }

    // -----------------------------------------------------------------------
    // QUIC dial and peering table registration
    // -----------------------------------------------------------------------

    /// Issue a QUIC dial and register the peer in the peering table.
    fn dialPeer(self: *PeerManager, node_id: [32]u8, addr: std.net.Address) void {
        // Convert std.net.Address to the ListenAddress expected by eth_ec_quic.
        var host_buf: [64]u8 = undefined;
        const host = addressToHostStr(addr, &host_buf) catch return;

        const remote = eth_ec_quic.ListenAddress{
            .host = host,
            .port = addr.getPort(),
        };

        eth_ec_quic.dial(&self.allocator, self.config.quic_config, remote) catch return;

        // Mark as warm in the connection pool.
        self.pool.promoteHot(node_id, std.time.nanoTimestamp()) catch return;

        // Register in the peering table.
        const eth_ec = self.node.enr_cache.get(node_id);
        const entry = peering_table.PeerEntry{
            .node_id = node_id,
            .udp_addr = addr,
            .eth_ec = eth_ec,
            .tier = .hot,
        };

        // Choose selfish or altruistic placement.
        if (eth_ec != null and eth_ec.?.schemes & self.config.scheme_mask != 0) {
            self.peers.upsertSelfish(entry) catch {};
        } else {
            self.peers.upsertAltruistic(entry) catch {};
        }
    }

    // -----------------------------------------------------------------------
    // Score-based eviction
    // -----------------------------------------------------------------------

    /// Remove peers from the selfish table whose composite score is below `floor`.
    pub fn evictBelow(self: *PeerManager, floor: i32) void {
        var i: usize = 0;
        while (i < self.peers.selfish.entries.items.len) {
            if (self.peers.selfish.entries.items[i].score.composite < floor) {
                const id = self.peers.selfish.entries.items[i].node_id;
                _ = self.peers.selfish.remove(id);
                self.pool.demote(id);
            } else {
                i += 1;
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Helper: convert std.net.Address to a host string
// ---------------------------------------------------------------------------

fn addressToHostStr(addr: std.net.Address, buf: *[64]u8) ![]const u8 {
    return switch (addr.any.family) {
        std.posix.AF.INET => {
            const bytes = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr));
            return std.fmt.bufPrint(buf, "{}.{}.{}.{}", .{
                bytes[0], bytes[1], bytes[2], bytes[3],
            });
        },
        std.posix.AF.INET6 => {
            // IPv6 — minimal representation.
            const bytes = addr.in6.sa.addr;
            return std.fmt.bufPrint(buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
                bytes[0],  bytes[1],  bytes[2],  bytes[3],
                bytes[4],  bytes[5],  bytes[6],  bytes[7],
                bytes[8],  bytes[9],  bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15],
            });
        },
        else => error.UnsupportedAddressFamily,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "addressToHostStr IPv4" {
    var buf: [64]u8 = undefined;
    const addr = std.net.Address.initIp4(.{ 192, 168, 1, 1 }, 9000);
    const s = try addressToHostStr(addr, &buf);
    try std.testing.expectEqualStrings("192.168.1.1", s);
}

test "evictBelow removes low-scoring peers" {
    const gpa = std.testing.allocator;
    var peers = peering_table.PeerTable.init(gpa);
    defer peers.deinit();

    var good = peering_table.PeerEntry{
        .node_id = [_]u8{1} ** 32,
        .udp_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9000),
    };
    good.score.composite = 100;

    var bad = peering_table.PeerEntry{
        .node_id = [_]u8{2} ** 32,
        .udp_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9001),
    };
    bad.score.composite = -150;

    try peers.upsertSelfish(good);
    try peers.upsertSelfish(bad);
    try std.testing.expectEqual(@as(usize, 2), peers.selfish.len());

    // Build a minimal PeerManager to call evictBelow.
    var node = try discv5_node.Node.init(gpa, .{ .local_privkey = [_]u8{5} ** 32 });
    defer node.deinit();
    var warmup = warmup_mod.Scheduler.init(gpa);
    defer warmup.deinit();
    var pool = pool_mod.Pool.init(gpa);
    defer pool.deinit();

    var pm = PeerManager.init(gpa, .{}, &node, &peers, &warmup, &pool);
    pm.evictBelow(-100);

    try std.testing.expectEqual(@as(usize, 1), peers.selfish.len());
    try std.testing.expect(peers.selfish.get([_]u8{1} ** 32) != null);
    try std.testing.expect(peers.selfish.get([_]u8{2} ** 32) == null);
}
