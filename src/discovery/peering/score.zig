//! Peer scoring model.
//!
//! RTT is the first-class signal. Scores are composites of RTT, reliability,
//! bandwidth, and behavioral history. They decay on a timer and update on
//! events (not heartbeats) — per the ethp2p spec §Peering.
//!
//! Latency tiers (inner/mid/outer) from the broadcast layer (002-ec-broadcast)
//! are derived directly from RTT and flow into chunk dispatch ordering.

const std = @import("std");

// ---------------------------------------------------------------------------
// Latency tiers (mirror of broadcast layer tiers, 002-ec-broadcast.md)
// ---------------------------------------------------------------------------

/// Inner tier — chunks sent first. RTT < 60 ms.
pub const rtt_inner_ms: u32 = 60;
/// Mid tier — second priority. RTT 60–120 ms.
pub const rtt_mid_ms: u32 = 120;
/// Outer tier — everything above rtt_mid_ms.
pub const LatencyTier = enum { inner, mid, outer };

pub fn latencyTier(rtt_ms: u32) LatencyTier {
    if (rtt_ms < rtt_inner_ms) return .inner;
    if (rtt_ms < rtt_mid_ms) return .mid;
    return .outer;
}

// ---------------------------------------------------------------------------
// Score decay
// ---------------------------------------------------------------------------

/// Half-life for score decay (ms). Scores halve every 30 minutes of inactivity.
pub const score_half_life_ms: u64 = 30 * 60 * 1_000;

/// Score floor — a peer at or below this is a candidate for eviction.
pub const score_floor: i32 = -100;

/// Score ceiling.
pub const score_ceiling: i32 = 1_000;

// ---------------------------------------------------------------------------
// Score components
// ---------------------------------------------------------------------------

pub const Score = struct {
    /// Round-trip time in milliseconds (u32 max = unknown).
    rtt_ms: u32 = std.math.maxInt(u32),

    /// Fraction of successful RPCs in [0, 255]. 255 = 100% success.
    reliability: u8 = 128,

    /// Estimated available bandwidth in KiB/s. 0 = unknown.
    bandwidth_kibps: u32 = 0,

    /// Behavioral delta: positive for helpful behaviour (fast replies, valid
    /// ENRs), negative for misbehaviour (invalid packets, timeouts).
    behavioral: i16 = 0,

    /// Composite score in [score_floor, score_ceiling].
    composite: i32 = 0,

    /// Monotonic timestamp of last update (ns). Used for decay.
    updated_ns: u64 = 0,

    // -----------------------------------------------------------------------
    // Updates (event-triggered, not heartbeat-based)
    // -----------------------------------------------------------------------

    /// Record a measured RTT and recompute the composite.
    pub fn recordRtt(self: *Score, rtt_ms: u32, now_ns: u64) void {
        // Exponential moving average: alpha = 0.25.
        if (self.rtt_ms == std.math.maxInt(u32)) {
            self.rtt_ms = rtt_ms;
        } else {
            self.rtt_ms = (self.rtt_ms * 3 + rtt_ms) / 4;
        }
        self.updated_ns = now_ns;
        self.recompute();
    }

    pub fn recordSuccess(self: *Score, now_ns: u64) void {
        self.behavioral = @intCast(@min(score_ceiling, @as(i32, self.behavioral) + 1));
        self.reliability = self.reliability +| 1;
        self.updated_ns = now_ns;
        self.recompute();
    }

    pub fn recordFailure(self: *Score, now_ns: u64) void {
        self.behavioral = @intCast(@max(score_floor, @as(i32, self.behavioral) - 5));
        self.reliability = self.reliability -| 3;
        self.updated_ns = now_ns;
        self.recompute();
    }

    /// Apply time-based decay.  Call periodically (e.g. on each poll tick).
    pub fn decay(self: *Score, now_ns: u64) void {
        if (self.updated_ns == 0) return;
        const elapsed_ms = (now_ns -| self.updated_ns) / std.time.ns_per_ms;
        if (elapsed_ms == 0) return;
        // Halve behavioral every half_life_ms.
        const halvings = elapsed_ms / score_half_life_ms;
        if (halvings > 0) {
            self.behavioral >>= @intCast(@min(halvings, 15));
            self.updated_ns = now_ns;
            self.recompute();
        }
    }

    // -----------------------------------------------------------------------
    // Composite calculation
    // -----------------------------------------------------------------------

    fn recompute(self: *Score) void {
        // RTT component: 0 for ≤1ms, up to -500 for very high RTT.
        const rtt_penalty: i32 = if (self.rtt_ms == std.math.maxInt(u32))
            -200
        else blk: {
            const r: i32 = @intCast(self.rtt_ms);
            break :blk -@min(500, @divTrunc(r, 2));
        };

        // Reliability component: 0 for 50% (128/255), ±100 for extremes.
        const rel: i32 = @divTrunc((@as(i32, self.reliability) - 128) * 100, 128);

        // Behavioral component (already bounded).
        const beh: i32 = self.behavioral;

        self.composite = std.math.clamp(rtt_penalty + rel + beh, score_floor, score_ceiling);
    }

    pub fn tier(self: *const Score) LatencyTier {
        return latencyTier(self.rtt_ms);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "latencyTier boundaries" {
    try std.testing.expectEqual(LatencyTier.inner, latencyTier(0));
    try std.testing.expectEqual(LatencyTier.inner, latencyTier(59));
    try std.testing.expectEqual(LatencyTier.mid, latencyTier(60));
    try std.testing.expectEqual(LatencyTier.mid, latencyTier(119));
    try std.testing.expectEqual(LatencyTier.outer, latencyTier(120));
    try std.testing.expectEqual(LatencyTier.outer, latencyTier(500));
}

test "recordRtt lowers composite for high RTT" {
    var s = Score{};
    s.recordRtt(300, 0);
    try std.testing.expect(s.composite < 0);
}

test "recordSuccess improves composite" {
    var s = Score{};
    s.recordRtt(30, 0);
    const before = s.composite;
    s.recordSuccess(1);
    try std.testing.expect(s.composite >= before);
}

test "recordFailure degrades composite" {
    var s = Score{};
    s.recordRtt(30, 0);
    const before = s.composite;
    s.recordFailure(1);
    try std.testing.expect(s.composite < before);
}

test "score stays within bounds" {
    var s = Score{};
    s.recordRtt(1, 0);
    for (0..200) |_| s.recordSuccess(1);
    try std.testing.expect(s.composite <= score_ceiling);
    for (0..200) |_| s.recordFailure(1);
    try std.testing.expect(s.composite >= score_floor);
}
