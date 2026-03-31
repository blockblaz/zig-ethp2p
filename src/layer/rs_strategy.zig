//! Unified per-session RS strategy (`broadcast/rs/strategy.go`).

const std = @import("std");
const bitmap_mod = @import("bitmap.zig");
const broadcast_types = @import("broadcast_types.zig");
const emit_planner = @import("emit_planner.zig");
const rs_encode = @import("rs_encode.zig");
const rs_init = @import("rs_init.zig");

const Allocator = std.mem.Allocator;
const Bitmap = bitmap_mod.Bitmap;
const EmitPlanner = emit_planner.EmitPlanner;
const ReedSolomon = rs_encode.ReedSolomon;
const RsConfig = rs_init.RsConfig;

pub const ChunkIdent = struct {
    index: i32,

    pub fn handle(self: ChunkIdent) broadcast_types.ChunkHandle {
        return @intCast(self.index);
    }
};

/// Preamble fields aligned with ethp2p `broadcast/rs/types.go` `Preamble`.
pub const RsPreamble = struct {
    data_chunks: i32,
    parity_chunks: i32,
    message_length: i32,
    chunk_hashes: [][]u8,
    message_hash: [32]u8,

    pub fn totalChunks(self: RsPreamble) usize {
        return @as(usize, @intCast(self.data_chunks)) + @as(usize, @intCast(self.parity_chunks));
    }

    pub fn deinit(self: *RsPreamble, allocator: Allocator) void {
        for (self.chunk_hashes) |row| allocator.free(row);
        allocator.free(self.chunk_hashes);
        self.chunk_hashes = &.{};
    }
};

fn clonePreamble(allocator: Allocator, src: *const RsPreamble) Allocator.Error!RsPreamble {
    const n = src.chunk_hashes.len;
    const hashes = try allocator.alloc([]u8, n);
    var i: usize = 0;
    errdefer {
        for (hashes[0..i]) |row| allocator.free(row);
        allocator.free(hashes);
    }
    while (i < n) : (i += 1) {
        hashes[i] = try allocator.dupe(u8, src.chunk_hashes[i]);
    }
    return .{
        .data_chunks = src.data_chunks,
        .parity_chunks = src.parity_chunks,
        .message_length = src.message_length,
        .chunk_hashes = hashes,
        .message_hash = src.message_hash,
    };
}

pub const PeerState = struct {
    bitmap: Bitmap,
    stats: *broadcast_types.PeerSessionStats,
    inflight: []i32,
    completed: bool,

    fn deinit(self: *PeerState, allocator: Allocator) void {
        self.bitmap.deinit(allocator);
        allocator.free(self.inflight);
    }
};

pub const RsStrategy = struct {
    allocator: Allocator,
    config: RsConfig,
    preamble: RsPreamble,
    is_origin: bool,
    total_chunks: usize,
    chunk_len: usize,
    /// Missing chunk: empty slice. Origin: subslices of `chunk_slab`.
    chunks: [][]u8,
    chunk_slab: ?[]u8,
    emit_planner: EmitPlanner,
    peers: std.StringHashMapUnmanaged(PeerState),
    routing_dirty: bool,
    seed: u64,
    have: Bitmap,
    complete: bool,

    pub fn deinit(self: *RsStrategy) void {
        const allocator = self.allocator;
        if (self.chunk_slab) |slab| {
            allocator.free(slab);
        } else {
            for (self.chunks) |c| {
                if (c.len != 0) allocator.free(c);
            }
        }
        allocator.free(self.chunks);
        self.preamble.deinit(allocator);
        self.emit_planner.deinit(allocator);

        var it = self.peers.iterator();
        while (it.next()) |kv| {
            allocator.free(@constCast(kv.key_ptr.*));
            kv.value_ptr.deinit(allocator);
        }
        self.peers.deinit(allocator);

        self.have.deinit(allocator);
    }

    pub fn newOrigin(allocator: Allocator, config: RsConfig, payload: []const u8) (Allocator.Error || rs_encode.EncodeError)!RsStrategy {
        const layout = rs_init.initPreamble(config, payload.len);
        const dc = @as(usize, @intCast(layout.data_chunks));
        const pc = @as(usize, @intCast(layout.parity_chunks));
        const tot = dc + pc;
        const cl = layout.chunk_len;

        var rs = try ReedSolomon.init(allocator, dc, pc);
        defer rs.deinit();

        const total_len = cl * tot;
        const slab = try allocator.alloc(u8, total_len);
        errdefer allocator.free(slab);
        @memcpy(slab[0..payload.len], payload);
        @memset(slab[payload.len..total_len], 0);

        var chunk_ptrs = try allocator.alloc([]u8, tot);
        errdefer allocator.free(chunk_ptrs);
        for (0..tot) |i| {
            chunk_ptrs[i] = slab[i * cl ..][0..cl];
        }

        rs.encode(chunk_ptrs, cl);

        const chunk_hashes = try allocator.alloc([]u8, tot);
        var hi: usize = 0;
        errdefer {
            for (chunk_hashes[0..hi]) |row| allocator.free(row);
            allocator.free(chunk_hashes);
        }
        while (hi < tot) : (hi += 1) {
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(chunk_ptrs[hi], &digest, .{});
            chunk_hashes[hi] = try allocator.dupe(u8, &digest);
        }

        var msg_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(payload, &msg_digest, .{});

        var preamble: RsPreamble = .{
            .data_chunks = layout.data_chunks,
            .parity_chunks = layout.parity_chunks,
            .message_length = layout.message_length,
            .chunk_hashes = chunk_hashes,
            .message_hash = msg_digest,
        };
        errdefer preamble.deinit(allocator);

        var planner = EmitPlanner.init(allocator);
        errdefer planner.deinit(allocator);
        for (0..tot) |i| {
            try planner.insert(allocator, .{ .idx = i, .times = 0, .sent = 0, .priority = 0 });
        }

        var have = try Bitmap.initAllOnes(allocator, tot);
        errdefer have.deinit(allocator);

        return .{
            .allocator = allocator,
            .config = config,
            .preamble = preamble,
            .is_origin = true,
            .total_chunks = tot,
            .chunk_len = cl,
            .chunks = chunk_ptrs,
            .chunk_slab = slab,
            .emit_planner = planner,
            .peers = .{},
            .routing_dirty = true,
            .seed = 0,
            .have = have,
            .complete = false,
        };
    }

    pub fn newRelay(allocator: Allocator, config: RsConfig, pre: *const RsPreamble) (Allocator.Error || error{InvalidPreamble})!RsStrategy {
        if (pre.chunk_hashes.len != pre.totalChunks()) return error.InvalidPreamble;

        var cfg = config;
        if (cfg.forward_multiplier == 0) {
            cfg.forward_multiplier = 4;
        }

        var preamble = try clonePreamble(allocator, pre);
        errdefer preamble.deinit(allocator);

        const tot = preamble.totalChunks();

        var seed: u64 = undefined;
        std.crypto.random.bytes(std.mem.asBytes(&seed));

        const chunks = try allocator.alloc([]u8, tot);
        errdefer allocator.free(chunks);
        for (chunks) |*slot| slot.* = &[_]u8{};

        var planner = EmitPlanner.init(allocator);
        errdefer planner.deinit(allocator);

        var have = try Bitmap.initEmpty(allocator, tot);
        errdefer have.deinit(allocator);

        return .{
            .allocator = allocator,
            .config = cfg,
            .preamble = preamble,
            .is_origin = false,
            .total_chunks = tot,
            .chunk_len = 0,
            .chunks = chunks,
            .chunk_slab = null,
            .emit_planner = planner,
            .peers = .{},
            .routing_dirty = true,
            .seed = seed,
            .have = have,
            .complete = false,
        };
    }

    pub fn haveChunk(self: *const RsStrategy, chunk_id: ChunkIdent) bool {
        const idx = chunk_id.index;
        if (idx < 0 or @as(usize, @intCast(idx)) >= self.total_chunks) return true;
        return self.have.get(@intCast(idx));
    }

    pub fn dedupKey(self: *const RsStrategy, chunk_id: ChunkIdent) [4]u8 {
        _ = self;
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, @bitCast(@as(i32, chunk_id.index)), .big);
        return buf;
    }

    pub fn attachPeer(self: *RsStrategy, peer: []const u8, stats: *broadcast_types.PeerSessionStats) Allocator.Error!void {
        const allocator = self.allocator;
        if (self.peers.fetchRemove(peer)) |kv| {
            allocator.free(kv.key);
            var ps = kv.value;
            ps.deinit(allocator);
        }

        const key = try allocator.dupe(u8, peer);
        errdefer allocator.free(key);

        var bm = try Bitmap.initEmpty(allocator, self.total_chunks);
        errdefer bm.deinit(allocator);
        const inflight = try allocator.alloc(i32, self.total_chunks);
        errdefer allocator.free(inflight);
        @memset(std.mem.sliceAsBytes(inflight), 0);

        try self.peers.put(allocator, key, .{
            .bitmap = bm,
            .stats = stats,
            .inflight = inflight,
            .completed = false,
        });
    }

    pub fn detachPeer(self: *RsStrategy, peer: []const u8, completed: bool) void {
        const allocator = self.allocator;
        if (self.peers.getEntry(peer)) |ent| {
            if (completed) {
                ent.value_ptr.completed = true;
                return;
            }
        } else return;

        if (self.peers.fetchRemove(peer)) |kv| {
            allocator.free(kv.key);
            var st = kv.value;
            st.deinit(allocator);
        }
    }

    pub fn verifyChunk(self: *const RsStrategy, chunk_id: ChunkIdent, data: []const u8) broadcast_types.Verdict {
        const idx = chunk_id.index;
        if (idx < 0 or @as(usize, @intCast(idx)) >= self.preamble.chunk_hashes.len) {
            return .invalid;
        }
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
        if (std.mem.eql(u8, &digest, self.preamble.chunk_hashes[@intCast(idx)])) {
            return .accepted;
        }
        return .invalid;
    }

    pub fn takeChunk(
        self: *RsStrategy,
        peer: []const u8,
        chunk_id: ChunkIdent,
        data: []const u8,
        dedup: ?*broadcast_types.DedupCancel,
    ) Allocator.Error!broadcast_types.ChunkIngestResult {
        const idx_i = chunk_id.index;
        if (idx_i < 0 or @as(usize, @intCast(idx_i)) >= self.total_chunks) {
            return .{ .verdict = .invalid, .complete = false };
        }
        const idx: usize = @intCast(idx_i);

        if (self.chunks[idx].len != 0) {
            return .{ .verdict = .redundant, .complete = false };
        }

        if (!self.is_origin and self.chunk_len == 0 and data.len != 0) {
            self.chunk_len = data.len;
        }

        const copy = try self.allocator.dupe(u8, data);
        self.chunks[idx] = copy;
        self.have.set(idx);
        self.routing_dirty = true;
        try self.emit_planner.insert(self.allocator, .{
            .idx = idx,
            .times = 0,
            .sent = 0,
            .priority = self.chunkPriority(idx),
        });

        broadcast_types.DedupCancel.cancel(dedup);

        if (self.peers.getPtr(peer)) |ps| {
            ps.bitmap.set(idx);
        }

        if (!self.complete and self.have.onesCount() >= @as(usize, @intCast(self.preamble.data_chunks))) {
            self.complete = true;
        }
        return .{ .verdict = .accepted, .complete = self.complete };
    }

    pub fn decode(self: *RsStrategy) (Allocator.Error || rs_encode.EncodeError)![]u8 {
        return self.tryDecode();
    }

    fn tryDecode(self: *RsStrategy) (Allocator.Error || rs_encode.EncodeError)![]u8 {
        const allocator = self.allocator;
        const tot = self.total_chunks;
        const dc = @as(usize, @intCast(self.preamble.data_chunks));
        const pc = @as(usize, @intCast(self.preamble.parity_chunks));
        const cl = blk: {
            if (self.chunk_len != 0) break :blk self.chunk_len;
            for (self.chunks) |c| {
                if (c.len != 0) break :blk c.len;
            }
            return error.TooFewShards;
        };
        const msg_len = @as(usize, @intCast(self.preamble.message_length));

        var work = try allocator.alloc([]u8, tot);
        defer allocator.free(work);
        var freed: []bool = try allocator.alloc(bool, tot);
        defer allocator.free(freed);
        @memset(freed, false);

        for (0..tot) |i| {
            if (self.chunks[i].len == 0) {
                work[i] = &[_]u8{};
            } else {
                work[i] = try allocator.dupe(u8, self.chunks[i]);
                freed[i] = true;
            }
        }
        defer {
            for (work, freed) |s, f| {
                if (f) allocator.free(s);
            }
        }

        const digest_expected = self.preamble.message_hash;
        const out = try rs_encode.decodeMessage(allocator, dc, pc, work, cl, msg_len, digest_expected);
        return out;
    }

    pub fn routingUpdate(self: *RsStrategy, peer: []const u8, update: ?Bitmap) Allocator.Error![]broadcast_types.ChunkHandle {
        const ps = self.peers.getPtr(peer) orelse return &[_]broadcast_types.ChunkHandle{};
        if (update) |u| {
            ps.bitmap.orInPlace(u);
        }
        var n_cancel: usize = 0;
        for (ps.inflight, 0..) |count, idx| {
            if (count > 0 and ps.bitmap.get(idx)) n_cancel += 1;
        }
        var out = try self.allocator.alloc(broadcast_types.ChunkHandle, n_cancel);
        var o: usize = 0;
        for (ps.inflight, 0..) |count, idx| {
            if (count > 0 and ps.bitmap.get(idx)) {
                out[o] = @intCast(idx);
                o += 1;
            }
        }
        return out;
    }

    pub fn pollChunks(self: *RsStrategy) (Allocator.Error || emit_planner.PlannerError)![]broadcast_types.ChunkDispatch(ChunkIdent) {
        const allocator = self.allocator;
        var list: std.ArrayListUnmanaged(broadcast_types.ChunkDispatch(ChunkIdent)) = .{};
        errdefer list.deinit(allocator);

        var it = self.peers.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.completed) continue;
            const peer = kv.key_ptr.*;
            if (try self.allocate(peer, kv.value_ptr)) |disp| {
                try list.append(allocator, disp);
            }
        }
        return try list.toOwnedSlice(allocator);
    }

    fn allocate(self: *RsStrategy, peer: []const u8, ps: *PeerState) (Allocator.Error || emit_planner.PlannerError)!?broadcast_types.ChunkDispatch(ChunkIdent) {
        const allocator = self.allocator;
        var skipped: std.ArrayListUnmanaged(emit_planner.EmitEntry) = .{};
        defer skipped.deinit(allocator);

        var found_idx: ?usize = null;
        while (self.emit_planner.len() > 0) {
            const ec = self.emit_planner.top().?;
            if (ps.bitmap.get(ec.idx) or ps.inflight[ec.idx] > 0 or
                (!self.is_origin and ec.sent >= @as(i32, @intCast(self.config.forward_multiplier))))
            {
                const popped = try self.emit_planner.popFront(allocator);
                try skipped.append(allocator, popped);
                continue;
            }
            found_idx = ec.idx;
            break;
        }

        for (skipped.items) |ec| {
            try self.emit_planner.insert(allocator, ec);
        }

        const fi = found_idx orelse return null;
        const data = self.chunks[fi];
        ps.inflight[fi] += 1;
        try self.emit_planner.increment(allocator, fi);

        return .{
            .peer = peer,
            .chunk_id = .{ .index = @intCast(fi) },
            .data = data,
        };
    }

    pub fn pollRouting(self: *RsStrategy, allocator: Allocator, force: bool) Allocator.Error!struct { bitmap: ?Bitmap, emit: bool } {
        if ((self.routing_dirty or force) and self.shouldEmitRouting()) {
            self.routing_dirty = false;
            const bm = try self.have.clone(allocator);
            return .{ .bitmap = bm, .emit = true };
        }
        return .{ .bitmap = null, .emit = false };
    }

    pub fn chunkSent(self: *RsStrategy, peer: []const u8, handle: broadcast_types.ChunkHandle, send_ok: bool) void {
        const ps = self.peers.getPtr(peer) orelse return;
        const idx: usize = @intCast(handle);
        if (idx >= self.total_chunks) return;
        if (ps.inflight[idx] <= 0) return;
        ps.inflight[idx] -= 1;

        if (send_ok) {
            ps.bitmap.set(idx);
            if (!self.is_origin) {
                self.emit_planner.addSent(idx, 1);
            }
        } else {
            ps.bitmap.unset(idx);
            if (!self.is_origin) {
                if (self.emit_planner.getSent(idx)) |sent| {
                    if (sent >= @as(i32, @intCast(self.config.forward_multiplier))) {
                        self.emit_planner.addSent(idx, -1);
                    }
                }
            }
        }
    }

    pub fn progress(self: *const RsStrategy) struct { have: usize, need: usize } {
        return .{
            .have = self.have.onesCount(),
            .need = @intCast(self.preamble.data_chunks),
        };
    }

    fn chunkPriority(self: *const RsStrategy, idx: usize) u32 {
        return @truncate((self.seed ^ @as(u64, @intCast(idx)) *% 0x9e3779b97f4a7c15) >> 32);
    }

    fn shouldEmitRouting(self: *const RsStrategy) bool {
        if (self.config.disable_bitmap) return false;
        if (self.config.bitmap_threshold == 0) return true;
        const pct = self.have.onesCount() * 100 / self.total_chunks;
        return pct >= @as(u32, @intCast(self.config.bitmap_threshold));
    }
};

test "origin decode roundtrip" {
    const gpa = std.testing.allocator;
    const msg = [_]u8{ 'h', 'e', 'l', 'l', 'o' };
    var strat = try RsStrategy.newOrigin(gpa, .{
        .data_shards = 4,
        .parity_shards = 2,
        .chunk_len = 0,
        .bitmap_threshold = 0,
        .forward_multiplier = 4,
        .disable_bitmap = false,
    }, &msg);
    defer strat.deinit();

    const out = try strat.decode();
    defer gpa.free(out);
    try std.testing.expectEqualSlices(u8, &msg, out);
}

test "relay takeChunk and decode" {
    const gpa = std.testing.allocator;
    const msg = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    const cfg = RsConfig{
        .data_shards = 4,
        .parity_shards = 2,
        .chunk_len = 0,
        .bitmap_threshold = 50,
        .forward_multiplier = 4,
        .disable_bitmap = false,
    };

    var origin = try RsStrategy.newOrigin(gpa, cfg, &msg);
    defer origin.deinit();

    var relay = try RsStrategy.newRelay(gpa, cfg, &origin.preamble);
    defer relay.deinit();

    const peer = "p";
    var stats: broadcast_types.PeerSessionStats = .{ .peer_id = peer };
    try relay.attachPeer(peer, &stats);

    var last_complete = false;
    for (0..4) |i| {
        const r = try relay.takeChunk(peer, .{ .index = @intCast(i) }, origin.chunks[i], null);
        try std.testing.expectEqual(broadcast_types.Verdict.accepted, r.verdict);
        last_complete = r.complete;
    }
    try std.testing.expect(last_complete);

    const decoded = try relay.decode();
    defer gpa.free(decoded);
    try std.testing.expectEqualSlices(u8, &msg, decoded);
}
