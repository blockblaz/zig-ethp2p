//! Abstract RS mesh (“simnet-style”) exercises `layer.RsStrategy` with the same RS settings and
//! topologies as ethp2p `sim/scenario_test.go` `TestNetwork`, without libp2p or Go simnet.
//!
//! This validates zig-ethp2p’s strategy layer under multi-hop chunk forwarding; it is not a UDP
//! timing simulation.

const std = @import("std");
const broadcast_types = @import("../layer/broadcast_types.zig");
const rs_init = @import("../layer/rs_init.zig");
const rs_strategy = @import("../layer/rs_strategy.zig");

const Allocator = std.mem.Allocator;
const RsConfig = rs_init.RsConfig;
const RsStrategy = rs_strategy.RsStrategy;

pub const Edge = struct { a: usize, b: usize };

pub const MeshParams = struct {
    node_count: usize,
    edges: []const Edge,
    cfg: RsConfig,
    payload: []const u8,
    max_rounds: usize,
};

fn nodeId(buf: *[8]u8, i: usize) []const u8 {
    return std.fmt.bufPrint(buf, "{d}", .{i}) catch unreachable;
}

fn indexOfPeer(nodes: []const MeshNode, peer: []const u8) ?usize {
    for (nodes, 0..) |n, i| {
        if (std.mem.eql(u8, n.id, peer)) return i;
    }
    return null;
}

const MeshNode = struct {
    id_buf: [8]u8 = undefined,
    id: []const u8 = &.{},
    strat: RsStrategy = undefined,
};

/// Run abstract RS broadcast until every non-origin node decodes `params.payload`, or `max_rounds`.
pub fn runAbstractRsMesh(gpa: Allocator, params: MeshParams) !void {
    const n = params.node_count;
    std.debug.assert(n >= 2);
    std.debug.assert(n <= MaxNodes);

    var nodes = try gpa.alloc(MeshNode, n);
    defer gpa.free(nodes);

    var deg: [MaxNodes]u8 = .{0} ** MaxNodes;
    var neigh: [MaxNodes][MaxNodes]u8 = .{.{0} ** MaxNodes} ** MaxNodes;

    for (params.edges) |e| {
        std.debug.assert(e.a < n and e.b < n and e.a != e.b);
        neigh[e.a][deg[e.a]] = @intCast(e.b);
        deg[e.a] += 1;
        neigh[e.b][deg[e.b]] = @intCast(e.a);
        deg[e.b] += 1;
    }

    for (nodes, 0..) |*node, i| {
        node.id = nodeId(&node.id_buf, i);
    }

    var built: usize = 0;
    defer {
        while (built > 0) {
            built -= 1;
            nodes[built].strat.deinit();
        }
    }

    nodes[0].strat = try RsStrategy.newOrigin(gpa, params.cfg, params.payload);
    built = 1;

    while (built < n) : (built += 1) {
        nodes[built].strat = try RsStrategy.newRelay(gpa, params.cfg, &nodes[0].strat.preamble);
    }

    var stats: [MaxNodes][MaxNodes]broadcast_types.PeerSessionStats = undefined;
    for (&stats) |*row| {
        for (row) |*cell| cell.* = .{ .peer_id = &.{} };
    }

    for (nodes, 0..) |*dst, di| {
        var k: u8 = 0;
        while (k < deg[di]) : (k += 1) {
            const j = neigh[di][k];
            try dst.strat.attachPeer(nodes[j].id, &stats[di][j]);
        }
    }

    var decoded = try gpa.alloc(?[]u8, n);
    defer {
        for (decoded) |d| if (d) |x| gpa.free(x);
        gpa.free(decoded);
    }
    @memset(decoded, null);

    var round: usize = 0;
    while (round < params.max_rounds) : (round += 1) {
        for (nodes) |*src| {
            const outgoing = try src.strat.pollChunks();
            defer gpa.free(outgoing);
            for (outgoing) |disp| {
                const dst_i = indexOfPeer(nodes, disp.peer) orelse continue;
                const r = try nodes[dst_i].strat.takeChunk(src.id, disp.chunk_id, disp.data, null);
                src.strat.chunkSent(disp.peer, disp.chunk_id.handle(), true);
                if (dst_i != 0 and r.complete and decoded[dst_i] == null) {
                    decoded[dst_i] = try nodes[dst_i].strat.decode();
                }
            }
        }

        try exchangeRouting(gpa, nodes[0..n], neigh, deg);

        var all = true;
        for (1..n) |j| {
            if (decoded[j] == null) {
                all = false;
                break;
            }
        }
        if (all) break;
    }

    for (1..n) |j| {
        const d = decoded[j] orelse return error.SimMeshIncomplete;
        try std.testing.expectEqualSlices(u8, params.payload, d);
    }

    while (built > 0) {
        built -= 1;
        nodes[built].strat.deinit();
    }
}

const MaxNodes = 8;

fn exchangeRouting(
    gpa: Allocator,
    nodes: []MeshNode,
    neigh: [MaxNodes][MaxNodes]u8,
    deg: [MaxNodes]u8,
) !void {
    for (nodes, 0..) |*src, si| {
        const pr = try src.strat.pollRouting(gpa, false);
        if (!pr.emit) continue;
        const bm = pr.bitmap orelse continue;
        defer bm.deinit(gpa);
        var k: u8 = 0;
        while (k < deg[si]) : (k += 1) {
            const j = neigh[si][k];
            const cancels = try nodes[j].strat.routingUpdate(src.id, bm);
            defer gpa.free(cancels);
        }
    }
}

// --- Topologies from ethp2p sim/scenario_test.go `TestNetwork` ---

const topo_two_nodes = [_]Edge{
    .{ .a = 0, .b = 1 },
};

const topo_four_ring = [_]Edge{
    .{ .a = 0, .b = 1 },
    .{ .a = 1, .b = 2 },
    .{ .a = 2, .b = 3 },
    .{ .a = 3, .b = 0 },
};

/// Eight-node ring (larger diameter than four-node ring; stress-scale coverage).
const topo_eight_ring = [_]Edge{
    .{ .a = 0, .b = 1 },
    .{ .a = 1, .b = 2 },
    .{ .a = 2, .b = 3 },
    .{ .a = 3, .b = 4 },
    .{ .a = 4, .b = 5 },
    .{ .a = 5, .b = 6 },
    .{ .a = 6, .b = 7 },
    .{ .a = 7, .b = 0 },
};

const topo_six_nodes = [_]Edge{
    .{ .a = 0, .b = 1 },
    .{ .a = 0, .b = 4 },
    .{ .a = 1, .b = 2 },
    .{ .a = 1, .b = 4 },
    .{ .a = 2, .b = 1 },
    .{ .a = 2, .b = 3 },
    .{ .a = 3, .b = 2 },
    .{ .a = 3, .b = 4 },
    .{ .a = 4, .b = 1 },
    .{ .a = 4, .b = 0 },
    .{ .a = 4, .b = 5 },
    .{ .a = 5, .b = 4 },
};

fn rsCfgDefault() RsConfig {
    return .{
        .data_shards = 16,
        .parity_shards = 16,
        .chunk_len = 0,
        .bitmap_threshold = 0,
        .forward_multiplier = 4,
        .disable_bitmap = false,
    };
}

fn rsCfgChunkLen() RsConfig {
    return .{
        .data_shards = 0,
        .parity_shards = 0,
        .chunk_len = 16 << 10,
        .bitmap_threshold = 0,
        .forward_multiplier = 4,
        .disable_bitmap = false,
    };
}

fn fillPayload(buf: []u8) void {
    for (buf, 0..) |*b, i| b.* = @truncate(i);
}

test "abstract RS mesh two nodes (simnet scenario topology 0)" {
    const gpa = std.testing.allocator;
    var payload: [10 * 1024]u8 = undefined;
    fillPayload(&payload);

    try runAbstractRsMesh(gpa, .{
        .node_count = 2,
        .edges = &topo_two_nodes,
        .cfg = rsCfgDefault(),
        .payload = &payload,
        .max_rounds = 50_000,
    });
}

test "abstract RS mesh four nodes ring (extra topology sanity)" {
    const gpa = std.testing.allocator;
    var payload: [2 * 1024]u8 = undefined;
    fillPayload(&payload);

    try runAbstractRsMesh(gpa, .{
        .node_count = 4,
        .edges = &topo_four_ring,
        .cfg = rsCfgDefault(),
        .payload = &payload,
        .max_rounds = 200_000,
    });
}

test "abstract RS mesh six nodes (simnet scenario topology 1)" {
    const gpa = std.testing.allocator;
    var payload: [10 * 1024]u8 = undefined;
    fillPayload(&payload);

    try runAbstractRsMesh(gpa, .{
        .node_count = 6,
        .edges = &topo_six_nodes,
        .cfg = rsCfgDefault(),
        .payload = &payload,
        .max_rounds = 2_000_000,
    });
}

test "abstract RS mesh six nodes fixed chunk len (simnet RS-ChunkLen)" {
    const gpa = std.testing.allocator;
    var payload: [10 * 1024]u8 = undefined;
    fillPayload(&payload);

    try runAbstractRsMesh(gpa, .{
        .node_count = 6,
        .edges = &topo_six_nodes,
        .cfg = rsCfgChunkLen(),
        .payload = &payload,
        .max_rounds = 2_000_000,
    });
}

test "abstract RS mesh six nodes env stress (ZIG_ETHP2P_STRESS=1)" {
    const builtin = @import("builtin");
    if (builtin.os.tag == .windows) return;

    const gpa = std.testing.allocator;
    const env = std.process.getEnvVarOwned(gpa, "ZIG_ETHP2P_STRESS") catch return;
    defer gpa.free(env);
    if (!std.mem.eql(u8, env, "1")) return;
    var payload: [10 * 1024]u8 = undefined;
    fillPayload(&payload);

    try runAbstractRsMesh(gpa, .{
        .node_count = 6,
        .edges = &topo_six_nodes,
        .cfg = rsCfgDefault(),
        .payload = &payload,
        .max_rounds = 3_000_000,
    });
}

/// Larger graph than default six-node `TestNetwork` topology 1; only with `ZIG_ETHP2P_STRESS=1`.
test "abstract RS mesh eight nodes ring env stress (large-network scale)" {
    const builtin = @import("builtin");
    if (builtin.os.tag == .windows) return;

    const gpa = std.testing.allocator;
    const env = std.process.getEnvVarOwned(gpa, "ZIG_ETHP2P_STRESS") catch return;
    defer gpa.free(env);
    if (!std.mem.eql(u8, env, "1")) return;

    var payload: [10 * 1024]u8 = undefined;
    fillPayload(&payload);

    try runAbstractRsMesh(gpa, .{
        .node_count = 8,
        .edges = &topo_eight_ring,
        .cfg = rsCfgDefault(),
        .payload = &payload,
        .max_rounds = 8_000_000,
    });
}
