//! Background SHA256 chunk checks feeding `VerifyQueue` (Go-style async verify workers).

const std = @import("std");
const broadcast_types = @import("broadcast_types.zig");
const verify_queue_mod = @import("verify_queue.zig");

const Allocator = std.mem.Allocator;

pub const VerifyJob = struct {
    handle: broadcast_types.ChunkHandle,
    expected_hash: [32]u8,
    data: []const u8,
};

pub const VerifyWorkerPool = struct {
    allocator: Allocator,
    pool: std.Thread.Pool,
    out: *verify_queue_mod.VerifyQueue,
    out_mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: Allocator, n_jobs: usize, out: *verify_queue_mod.VerifyQueue) !VerifyWorkerPool {
        var pool: std.Thread.Pool = undefined;
        try pool.init(.{ .allocator = allocator, .n_jobs = n_jobs });
        return .{
            .allocator = allocator,
            .pool = pool,
            .out = out,
        };
    }

    pub fn deinit(self: *VerifyWorkerPool) void {
        self.pool.deinit();
    }

    /// Queue work on the pool; `job.data` is copied.
    pub fn schedule(self: *VerifyWorkerPool, job: VerifyJob) !void {
        const owned = try self.allocator.dupe(u8, job.data);
        errdefer self.allocator.free(owned);
        try self.pool.spawn(runOne, .{ self, job.handle, job.expected_hash, owned });
    }

    /// Same as `schedule`, but increments `wg` before enqueue and finishes after the result is pushed.
    pub fn scheduleWait(self: *VerifyWorkerPool, wg: *std.Thread.WaitGroup, job: VerifyJob) !void {
        const owned = try self.allocator.dupe(u8, job.data);
        errdefer self.allocator.free(owned);
        self.pool.spawnWg(wg, runOne, .{ self, job.handle, job.expected_hash, owned });
    }

    /// Synchronous path (no pool thread): hash, push, free copy.
    pub fn verifyInline(self: *VerifyWorkerPool, job: VerifyJob) Allocator.Error!void {
        const owned = try self.allocator.dupe(u8, job.data);
        defer self.allocator.free(owned);
        runOne(self, job.handle, job.expected_hash, owned);
    }
};

fn runOne(
    parent: *VerifyWorkerPool,
    handle: broadcast_types.ChunkHandle,
    expected: [32]u8,
    data: []u8,
) void {
    defer parent.allocator.free(data);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    const verdict: broadcast_types.Verdict = if (std.mem.eql(u8, &digest, &expected))
        .accepted
    else
        .invalid;

    parent.out_mutex.lock();
    defer parent.out_mutex.unlock();
    parent.out.push(parent.allocator, .{ .handle = handle, .verdict = verdict }) catch {
        @panic("VerifyWorkerPool: out queue OOM");
    };
}

test "verify worker pool inline pushes verdicts" {
    const gpa = std.testing.allocator;

    var q: verify_queue_mod.VerifyQueue = .{};
    defer q.deinit(gpa);

    var pool = try VerifyWorkerPool.init(gpa, 2, &q);
    defer pool.deinit();

    var good: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("ok", &good, .{});

    try pool.verifyInline(.{ .handle = 7, .expected_hash = good, .data = "ok" });
    try pool.verifyInline(.{ .handle = 8, .expected_hash = good, .data = "bad" });

    const r0 = q.popFront().?;
    const r1 = q.popFront().?;
    try std.testing.expect(q.popFront() == null);

    var saw7_accept = false;
    var saw8_invalid = false;
    for ([_]verify_queue_mod.VerifyRecord{ r0, r1 }) |r| {
        if (r.handle == 7 and r.verdict == .accepted) saw7_accept = true;
        if (r.handle == 8 and r.verdict == .invalid) saw8_invalid = true;
    }
    try std.testing.expect(saw7_accept);
    try std.testing.expect(saw8_invalid);
}
