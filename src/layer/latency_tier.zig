//! RTT → latency tier for RS chunk dispatch and peering (002-ec-broadcast).

const std = @import("std");

/// Inner tier — chunks sent first. RTT < 60 ms.
pub const rtt_inner_ms: u32 = 60;
/// Mid tier — second priority. RTT 60–120 ms.
pub const rtt_mid_ms: u32 = 120;
/// Outer tier — everything above `rtt_mid_ms`.
pub const LatencyTier = enum { inner, mid, outer };

pub fn latencyTier(rtt_ms: u32) LatencyTier {
    if (rtt_ms < rtt_inner_ms) return .inner;
    if (rtt_ms < rtt_mid_ms) return .mid;
    return .outer;
}

test "latencyTier boundaries" {
    try std.testing.expectEqual(LatencyTier.inner, latencyTier(0));
    try std.testing.expectEqual(LatencyTier.inner, latencyTier(59));
    try std.testing.expectEqual(LatencyTier.mid, latencyTier(60));
    try std.testing.expectEqual(LatencyTier.mid, latencyTier(119));
    try std.testing.expectEqual(LatencyTier.outer, latencyTier(120));
    try std.testing.expectEqual(LatencyTier.outer, latencyTier(500));
}
