//! Duty-type definitions and per-duty peer slot capacities.
//!
//! The selfish segment of the peer table is divided into duty-typed slots.
//! Each duty type has a fixed number of peer slots; the duty scheduler
//! (Control layer) fills them before the relevant slot phase begins.
//!
//! Slot counts are derived from the ethp2p spec §Peering and Ethereum
//! committee/subnet sizes.

const std = @import("std");

// ---------------------------------------------------------------------------
// Duty types (mirrors ethp2p spec §Peering strategic peering dispatch)
// ---------------------------------------------------------------------------

pub const DutyKind = enum {
    /// Block proposer: needs high-fanout, geographic diversity.
    proposer,
    /// Attester: needs peers in the same attestation subnet.
    attester,
    /// Aggregator: needs subnet peers plus global reach.
    aggregator,
    /// Sync committee: needs persistent connections with stable RTT.
    sync_committee,
    /// PTC (Payload Timeliness Committee): current committee peers.
    ptc,
    /// DAS column custody: peers that hold specific column indices.
    das_custody,
};

// ---------------------------------------------------------------------------
// Selfish slot capacities per duty type
// ---------------------------------------------------------------------------

/// Proposer peers: high fanout, geographically diverse.
pub const slots_proposer: usize = 16;

/// Attester peers: one slot per attestation subnet.
pub const slots_attester: usize = 64;

/// Aggregator peers: subnet peers + global relay.
pub const slots_aggregator: usize = 16;

/// Sync committee peers: persistent, low-RTT.
pub const slots_sync_committee: usize = 8;

/// PTC peers: current committee membership.
pub const slots_ptc: usize = 16;

/// DAS custody peers: one per monitored custody column.
pub const slots_das_custody: usize = 128;

/// Total selfish slots across all duty types.
pub const total_selfish_slots: usize =
    slots_proposer +
    slots_attester +
    slots_aggregator +
    slots_sync_committee +
    slots_ptc +
    slots_das_custody;

// ---------------------------------------------------------------------------
// Altruistic slot capacity
// ---------------------------------------------------------------------------

/// Peers reserved for chain sync, bootstrapping, and light client support.
pub const altruistic_slots: usize = 50;

// ---------------------------------------------------------------------------
// Total peer table capacity
// ---------------------------------------------------------------------------

pub const total_slots: usize = total_selfish_slots + altruistic_slots;

// ---------------------------------------------------------------------------
// Connection pool tier capacities (spec: tier1 validator-proven,
// tier2 high-quality, tier3 transient)
// ---------------------------------------------------------------------------

pub const tier1_capacity: usize = 20;
pub const tier2_capacity: usize = 80;
pub const tier3_capacity: usize = 100;

pub const total_pool_capacity: usize = tier1_capacity + tier2_capacity + tier3_capacity;

// ---------------------------------------------------------------------------
// Duty → selection requirements
// ---------------------------------------------------------------------------

pub const SelectionReq = struct {
    /// Minimum EC scheme bitmask the peer must advertise.
    scheme_mask: u16 = 0,
    /// Maximum acceptable RTT for this duty (ms).  0 = no constraint.
    max_rtt_ms: u32 = 0,
    /// Whether geographic diversity is required.
    require_geo_diversity: bool = false,
};

pub fn selectionReq(duty: DutyKind) SelectionReq {
    return switch (duty) {
        .proposer => .{
            .max_rtt_ms = 200,
            .require_geo_diversity = true,
        },
        .attester => .{
            .max_rtt_ms = 500,
        },
        .aggregator => .{
            .max_rtt_ms = 300,
        },
        .sync_committee => .{
            .max_rtt_ms = 1_000,
        },
        .ptc => .{
            .max_rtt_ms = 200,
        },
        .das_custody => .{
            .max_rtt_ms = 1_000,
        },
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "duty slot totals are consistent" {
    try std.testing.expectEqual(
        slots_proposer + slots_attester + slots_aggregator +
            slots_sync_committee + slots_ptc + slots_das_custody,
        total_selfish_slots,
    );
    try std.testing.expectEqual(total_selfish_slots + altruistic_slots, total_slots);
}

test "pool tier total is consistent" {
    try std.testing.expectEqual(
        tier1_capacity + tier2_capacity + tier3_capacity,
        total_pool_capacity,
    );
}

test "proposer requires geo diversity" {
    const req = selectionReq(.proposer);
    try std.testing.expect(req.require_geo_diversity);
}

test "sync_committee allows higher RTT than proposer" {
    const prop = selectionReq(.proposer);
    const sync = selectionReq(.sync_committee);
    try std.testing.expect(sync.max_rtt_ms > prop.max_rtt_ms);
}
