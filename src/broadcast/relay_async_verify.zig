//! Async SHA256 verify via `VerifyWorkerPool`, then single-threaded `drainCompleted` → `relayIngestChunk`.
//! Callers must use a **thread-safe** `pool_alloc` when `n_jobs > 0` (e.g. `std.heap.page_allocator`).

const std = @import("std");
const broadcast_types = @import("../layer/broadcast_types.zig");
const dedup_registry_mod = @import("../layer/dedup_registry.zig");
const rs_strategy = @import("../layer/rs_strategy.zig");
const verify_queue_mod = @import("../layer/verify_queue.zig");
const verify_workers_mod = @import("../layer/verify_workers.zig");
const ChannelRs = @import("channel_rs.zig").ChannelRs;

const Allocator = std.mem.Allocator;

pub const RelayAsyncVerifier = struct {
    allocator: Allocator,
    channel: *ChannelRs,
    registry: ?*dedup_registry_mod.DedupRegistry,
    out_q: verify_queue_mod.VerifyQueue,
    pool: verify_workers_mod.VerifyWorkerPool,
    pending: std.AutoHashMapUnmanaged(u64, Pending) = .{},
    mu: std.Thread.Mutex = .{},
    next_handle: std.atomic.Value(u64) = .init(1),

    pub const Pending = struct {
        peer: []u8,
        message_id: []u8,
        chunk_id: rs_strategy.ChunkIdent,
        data: []u8,
        dedup: ?*broadcast_types.DedupCancel,
    };

    pub const Error = Allocator.Error || error{
        UnknownMessage,
        InvalidChunkIndex,
        OrphanVerifyRecord,
        SystemResources,
        Unexpected,
        LockedMemoryLimitExceeded,
        ThreadQuotaExceeded,
    };

    /// `pool_alloc` must be thread-safe if `n_jobs > 0`. `allocator` is for pending metadata and `out_q` (main thread).
    pub fn init(
        allocator: Allocator,
        pool_alloc: Allocator,
        n_jobs: usize,
        channel: *ChannelRs,
        registry: ?*dedup_registry_mod.DedupRegistry,
    ) Error!RelayAsyncVerifier {
        var self: RelayAsyncVerifier = .{
            .allocator = allocator,
            .channel = channel,
            .registry = registry,
            .out_q = .{},
            .pool = undefined,
        };
        self.pool = try verify_workers_mod.VerifyWorkerPool.init(pool_alloc, n_jobs, &self.out_q);
        return self;
    }

    pub fn deinit(self: *RelayAsyncVerifier) void {
        self.pool.deinit();
        while (self.out_q.popFront()) |rec| {
            self.dropCompleted(rec);
        }
        self.out_q.deinit(self.allocator);
        var it = self.pending.iterator();
        while (it.next()) |ent| {
            freePendingSlices(self.allocator, ent.value_ptr.*);
        }
        self.pending.deinit(self.allocator);
    }

    fn dropCompleted(self: *RelayAsyncVerifier, rec: verify_queue_mod.VerifyRecord) void {
        self.mu.lock();
        const prev = self.pending.fetchRemove(rec.handle);
        self.mu.unlock();
        if (prev) |kv| {
            freePendingSlices(self.allocator, kv.value);
        }
    }

    /// Enqueue async verify. When results appear on the internal queue, call `drainCompleted` from the **same** thread that owns `channel`.
    pub fn submit(
        self: *RelayAsyncVerifier,
        message_id: []const u8,
        peer: []const u8,
        chunk_id: rs_strategy.ChunkIdent,
        data: []const u8,
        dedup: ?*broadcast_types.DedupCancel,
    ) Error!void {
        const strat = self.channel.sessionStrategy(message_id) orelse return error.UnknownMessage;
        const idx_i = chunk_id.index;
        if (idx_i < 0) return error.InvalidChunkIndex;
        const idx: usize = @intCast(idx_i);
        if (idx >= strat.preamble.chunk_hashes.len) return error.InvalidChunkIndex;

        var expected: [32]u8 = undefined;
        @memcpy(&expected, strat.preamble.chunk_hashes[idx][0..32]);

        const handle = self.next_handle.fetchAdd(1, .monotonic);

        const peer_o = try self.allocator.dupe(u8, peer);
        errdefer self.allocator.free(peer_o);
        const mid_o = try self.allocator.dupe(u8, message_id);
        errdefer self.allocator.free(mid_o);
        const data_o = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(data_o);

        self.mu.lock();
        try self.pending.put(self.allocator, handle, .{
            .peer = peer_o,
            .message_id = mid_o,
            .chunk_id = chunk_id,
            .data = data_o,
            .dedup = dedup,
        });
        self.mu.unlock();

        self.pool.schedule(.{
            .handle = handle,
            .expected_hash = expected,
            .data = data,
        }) catch |err| {
            self.mu.lock();
            if (self.pending.fetchRemove(handle)) |kv| {
                self.mu.unlock();
                freePendingSlices(self.allocator, kv.value);
            } else {
                self.mu.unlock();
            }
            return err;
        };
    }

    /// `scheduleWait` + `WaitGroup.wait` + `drainCompleted(1)` for tests and blocking drivers.
    pub fn submitAwaitApply(
        self: *RelayAsyncVerifier,
        message_id: []const u8,
        peer: []const u8,
        chunk_id: rs_strategy.ChunkIdent,
        data: []const u8,
        dedup: ?*broadcast_types.DedupCancel,
    ) Error!void {
        const strat = self.channel.sessionStrategy(message_id) orelse return error.UnknownMessage;
        const idx_i = chunk_id.index;
        if (idx_i < 0) return error.InvalidChunkIndex;
        const idx: usize = @intCast(idx_i);
        if (idx >= strat.preamble.chunk_hashes.len) return error.InvalidChunkIndex;

        var expected: [32]u8 = undefined;
        @memcpy(&expected, strat.preamble.chunk_hashes[idx][0..32]);

        const handle = self.next_handle.fetchAdd(1, .monotonic);

        const peer_o = try self.allocator.dupe(u8, peer);
        errdefer self.allocator.free(peer_o);
        const mid_o = try self.allocator.dupe(u8, message_id);
        errdefer self.allocator.free(mid_o);
        const data_o = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(data_o);

        self.mu.lock();
        try self.pending.put(self.allocator, handle, .{
            .peer = peer_o,
            .message_id = mid_o,
            .chunk_id = chunk_id,
            .data = data_o,
            .dedup = dedup,
        });
        self.mu.unlock();

        var wg: std.Thread.WaitGroup = .{};
        self.pool.scheduleWait(&wg, .{
            .handle = handle,
            .expected_hash = expected,
            .data = data,
        }) catch |err| {
            self.mu.lock();
            if (self.pending.fetchRemove(handle)) |kv| {
                self.mu.unlock();
                freePendingSlices(self.allocator, kv.value);
            } else {
                self.mu.unlock();
            }
            return err;
        };
        wg.wait();

        const n = try self.drainCompleted(1);
        if (n != 1) return error.OrphanVerifyRecord;
    }

    /// Pop up to `max` completed verify records and run `relayIngestChunk` for `.accepted`.
    pub fn drainCompleted(self: *RelayAsyncVerifier, max: usize) Error!usize {
        var done: usize = 0;
        var i: usize = 0;
        while (i < max) : (i += 1) {
            const rec = self.out_q.popFront() orelse break;

            self.mu.lock();
            const prev = self.pending.fetchRemove(rec.handle);
            self.mu.unlock();

            const kv = prev orelse return error.OrphanVerifyRecord;
            const pend = kv.value;
            if (rec.verdict == .accepted) {
                _ = try self.channel.relayIngestChunk(
                    self.registry,
                    pend.message_id,
                    pend.peer,
                    pend.chunk_id,
                    pend.data,
                    pend.dedup,
                );
            }
            freePendingSlices(self.allocator, pend);
            done += 1;
        }
        return done;
    }
};

fn freePendingSlices(allocator: Allocator, p: RelayAsyncVerifier.Pending) void {
    allocator.free(p.peer);
    allocator.free(p.message_id);
    allocator.free(p.data);
}

test "relay async verify submitAwaitApply ingests chunk" {
    const gpa = std.testing.allocator;
    var eng = try @import("engine.zig").Engine.init(gpa, "local", .{});
    defer eng.deinit();

    const cfg = @import("../layer/rs_init.zig").RsConfig{
        .data_shards = 4,
        .parity_shards = 2,
        .chunk_len = 0,
        .bitmap_threshold = 0,
        .forward_multiplier = 4,
        .disable_bitmap = false,
    };

    const ch = try eng.attachChannelRs("topic", cfg);
    try ch.addMember("peerA");

    const payload = [_]u8{ 1, 2, 3, 4 };
    var origin = try rs_strategy.RsStrategy.newOrigin(gpa, cfg, &payload);
    defer origin.deinit();

    try ch.attachRelaySession("m1", &origin.preamble);

    var verifier = try RelayAsyncVerifier.init(gpa, std.heap.page_allocator, 1, ch, null);
    defer verifier.deinit();

    const c0 = origin.chunks[0];
    try verifier.submitAwaitApply("m1", "peerA", .{ .index = 0 }, c0, null);

    const st = ch.sessionStrategy("m1").?;
    try std.testing.expect(st.haveChunk(.{ .index = 0 }));
}

test "relay async verify invalid chunk does not ingest" {
    const gpa = std.testing.allocator;
    var eng = try @import("engine.zig").Engine.init(gpa, "local", .{});
    defer eng.deinit();

    const cfg = @import("../layer/rs_init.zig").RsConfig{
        .data_shards = 4,
        .parity_shards = 2,
        .chunk_len = 0,
        .bitmap_threshold = 0,
        .forward_multiplier = 4,
        .disable_bitmap = false,
    };

    const ch = try eng.attachChannelRs("topic", cfg);
    try ch.addMember("peerA");

    const payload = [_]u8{ 9, 9, 9 };
    var origin = try rs_strategy.RsStrategy.newOrigin(gpa, cfg, &payload);
    defer origin.deinit();

    try ch.attachRelaySession("m1", &origin.preamble);

    var verifier = try RelayAsyncVerifier.init(gpa, std.heap.page_allocator, 1, ch, null);
    defer verifier.deinit();

    var bad = try gpa.dupe(u8, origin.chunks[0]);
    defer gpa.free(bad);
    if (bad.len > 0) bad[0] +%= 1;

    try verifier.submitAwaitApply("m1", "peerA", .{ .index = 0 }, bad, null);

    const st = ch.sessionStrategy("m1").?;
    try std.testing.expect(!st.haveChunk(.{ .index = 0 }));
}
