//! Slot-phase-aware connection warmup scheduler.
//!
//! During the idle phase of each slot (8–12 s into a 12 s slot), the scheduler
//! selects peers that will be needed in the next `lookahead_slots` slots and
//! issues proactive QUIC dials to warm their connections.
//!
//! Warming is non-blocking: dial requests are enqueued; the transport drives
//! them via the existing poll loop (eth_ec_quic.dial → PeerConn).
//!
//! Reference: ethp2p spec §Peering "session resumption mechanics".

const std = @import("std");

// ---------------------------------------------------------------------------
// Slot timing constants (12 s slots, 4 phases)
// ---------------------------------------------------------------------------

/// Full slot duration in milliseconds.
pub const slot_duration_ms: u64 = 12_000;

/// End of block-arrival phase.
pub const phase_block_end_ms: u64 = 2_000;

/// End of attestation phase.
pub const phase_attestation_end_ms: u64 = 4_000;

/// End of aggregation phase.
pub const phase_aggregation_end_ms: u64 = 8_000;

/// Start of idle/prep phase (same as aggregation end).
pub const phase_idle_start_ms: u64 = 8_000;

/// Number of slots to look ahead when warming connections.
pub const lookahead_slots: u64 = 2;

// ---------------------------------------------------------------------------
// Slot phase
// ---------------------------------------------------------------------------

pub const SlotPhase = enum {
    /// 0–2 s: block propagation has priority.
    block,
    /// 2–4 s: attestation window.
    attestation,
    /// 4–8 s: aggregation window.
    aggregation,
    /// 8–12 s: idle; warm connections for upcoming duties.
    idle,
};

/// Determine the current slot phase from `offset_ms` within the slot.
pub fn currentPhase(offset_ms: u64) SlotPhase {
    if (offset_ms < phase_block_end_ms) return .block;
    if (offset_ms < phase_attestation_end_ms) return .attestation;
    if (offset_ms < phase_aggregation_end_ms) return .aggregation;
    return .idle;
}

/// Milliseconds remaining in the current slot phase.
pub fn phaseRemaining(offset_ms: u64) u64 {
    return switch (currentPhase(offset_ms)) {
        .block => phase_block_end_ms -| offset_ms,
        .attestation => phase_attestation_end_ms -| offset_ms,
        .aggregation => phase_aggregation_end_ms -| offset_ms,
        .idle => slot_duration_ms -| offset_ms,
    };
}

// ---------------------------------------------------------------------------
// Warmup request
// ---------------------------------------------------------------------------

pub const WarmupRequest = struct {
    /// NodeId of the peer to warm.
    node_id: [32]u8,
    /// UDP address for discv5 / QUIC dial.
    addr: std.net.Address,
    /// Target slot for which this connection is needed.
    target_slot: u64,
};

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

pub const Scheduler = struct {
    allocator: std.mem.Allocator,
    /// Queue of outbound warmup requests (FIFO).
    queue: std.ArrayListUnmanaged(WarmupRequest) = .{},
    /// Current slot number (updated by caller at each slot boundary).
    current_slot: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) Scheduler {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Scheduler) void {
        self.queue.deinit(self.allocator);
    }

    /// Advance to the next slot. Clears requests for past slots.
    pub fn advanceSlot(self: *Scheduler, slot: u64) void {
        self.current_slot = slot;
        // Remove requests for slots already passed.
        var i: usize = 0;
        while (i < self.queue.items.len) {
            if (self.queue.items[i].target_slot < slot) {
                _ = self.queue.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Enqueue a warmup request for a peer needed at `target_slot`.
    /// Only accepted during the idle phase of the preceding slot.
    pub fn enqueue(
        self: *Scheduler,
        req: WarmupRequest,
        slot_offset_ms: u64,
    ) std.mem.Allocator.Error!bool {
        if (currentPhase(slot_offset_ms) != .idle) return false;
        if (req.target_slot > self.current_slot + lookahead_slots) return false;
        try self.queue.append(self.allocator, req);
        return true;
    }

    /// Drain all pending warmup requests into `out`.
    /// Returns the number of requests written.
    pub fn drain(self: *Scheduler, out: []WarmupRequest) usize {
        const n = @min(out.len, self.queue.items.len);
        @memcpy(out[0..n], self.queue.items[0..n]);
        self.queue.replaceRangeAssumeCapacity(0, n, &.{});
        return n;
    }

    pub fn pendingCount(self: *const Scheduler) usize {
        return self.queue.items.len;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "currentPhase boundaries" {
    try std.testing.expectEqual(SlotPhase.block, currentPhase(0));
    try std.testing.expectEqual(SlotPhase.block, currentPhase(1_999));
    try std.testing.expectEqual(SlotPhase.attestation, currentPhase(2_000));
    try std.testing.expectEqual(SlotPhase.attestation, currentPhase(3_999));
    try std.testing.expectEqual(SlotPhase.aggregation, currentPhase(4_000));
    try std.testing.expectEqual(SlotPhase.aggregation, currentPhase(7_999));
    try std.testing.expectEqual(SlotPhase.idle, currentPhase(8_000));
    try std.testing.expectEqual(SlotPhase.idle, currentPhase(11_999));
}

test "scheduler accepts request only during idle phase" {
    const gpa = std.testing.allocator;
    var sched = Scheduler.init(gpa);
    defer sched.deinit();

    const req = WarmupRequest{
        .node_id = [_]u8{1} ** 32,
        .addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9000),
        .target_slot = 1,
    };

    // During block phase — rejected.
    const accepted_block = try sched.enqueue(req, 500);
    try std.testing.expect(!accepted_block);

    // During idle phase — accepted.
    const accepted_idle = try sched.enqueue(req, 9_000);
    try std.testing.expect(accepted_idle);
    try std.testing.expectEqual(@as(usize, 1), sched.pendingCount());
}

test "advanceSlot purges stale requests" {
    const gpa = std.testing.allocator;
    var sched = Scheduler.init(gpa);
    defer sched.deinit();

    try sched.queue.append(gpa, .{
        .node_id = [_]u8{1} ** 32,
        .addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9000),
        .target_slot = 0,
    });
    sched.advanceSlot(1);
    try std.testing.expectEqual(@as(usize, 0), sched.pendingCount());
}

test "slot timing constants add up to one slot" {
    try std.testing.expectEqual(slot_duration_ms, @as(u64, 12_000));
    try std.testing.expect(phase_idle_start_ms < slot_duration_ms);
    try std.testing.expectEqual(phase_aggregation_end_ms, phase_idle_start_ms);
}
