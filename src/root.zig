//! Zig implementation of [ethp2p](https://github.com/ethp2p/ethp2p) wire formats.
//! Behavior is validated against the reference Go stack; see `UPSTREAM.md`.

pub const wire = @import("wire/root.zig");

/// Abstract multi-hop RS scenarios aligned with ethp2p `sim/scenario_test.go` (strategy-only; no libp2p).
pub const sim = struct {
    pub const rs_mesh = @import("sim/rs_mesh.zig");
};

/// Higher-level broadcast / RS helpers aligned with ethp2p `broadcast/` (not wire-only).
pub const layer = struct {
    pub const bitmap = @import("layer/bitmap.zig");
    pub const broadcast_types = @import("layer/broadcast_types.zig");
    pub const emit_planner = @import("layer/emit_planner.zig");
    pub const rs_encode = @import("layer/rs_encode.zig");
    pub const rs_init = @import("layer/rs_init.zig");
    pub const rs_strategy = @import("layer/rs_strategy.zig");
};

test {
    _ = wire;
    _ = layer;
    _ = sim.rs_mesh;
}
