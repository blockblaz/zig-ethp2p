//! Zig implementation of [ethp2p](https://github.com/ethp2p/ethp2p) wire formats.
//! Behavior is validated against the reference Go stack; see `UPSTREAM.md`.
//! Split CI test roots live in `ci_root_broadcast.zig`, `ci_root_sim_rs.zig`, and `ci_root_sim_gossipsub.zig`; update them when adding tests under those areas.

pub const wire = @import("wire/root.zig");

/// Abstract multi-hop RS scenarios aligned with ethp2p `sim/scenario_test.go` (strategy-only; no libp2p).
/// `rs_mesh.MeshParams.partition` models link outage + heal (upstream simnet-rs CI also matches `TestNodeReconnection`, which is not implemented in Go on ethp2p `main` today).
pub const sim = struct {
    pub const rs_mesh = @import("sim/rs_mesh.zig");
    pub const gossipsub_transport = @import("sim/gossipsub_transport.zig");
    pub const gossipsub_protocol = @import("sim/gossipsub_protocol.zig");
    pub const gossipsub_broadcast = @import("sim/gossipsub_broadcast.zig");
    pub const gossipsub_interop = @import("sim/gossipsub_interop.zig");
    pub const gossipsub_rpc_pb = @import("sim/gossipsub_rpc_pb.zig");
    pub const gossipsub_rpc_host = @import("sim/gossipsub_rpc_host.zig");
};

/// Higher-level broadcast / RS helpers aligned with ethp2p `broadcast/` (not wire-only).
pub const layer = struct {
    pub const bitmap = @import("layer/bitmap.zig");
    pub const broadcast_types = @import("layer/broadcast_types.zig");
    pub const ec_scheme = @import("layer/ec_scheme.zig");
    pub const emit_planner = @import("layer/emit_planner.zig");
    pub const rs_encode = @import("layer/rs_encode.zig");
    pub const rs_init = @import("layer/rs_init.zig");
    pub const rs_strategy = @import("layer/rs_strategy.zig");
    pub const dedup = @import("layer/dedup.zig");
    pub const dedup_registry = @import("layer/dedup_registry.zig");
    pub const verify_queue = @import("layer/verify_queue.zig");
    pub const verify_workers = @import("layer/verify_workers.zig");
};

/// Session / engine / RS channel stack aligned with ethp2p `broadcast/` (single-threaded `drive` style).
pub const broadcast = struct {
    pub const observer = @import("broadcast/observer.zig");
    pub const engine = @import("broadcast/engine.zig");
    pub const channel_rs = @import("broadcast/channel_rs.zig");
    pub const session_rs = @import("broadcast/session_rs.zig");
    pub const gossip = @import("broadcast/gossip.zig");
    pub const relay_async_verify = @import("broadcast/relay_async_verify.zig");
};

test {
    _ = wire;
    _ = layer;
    _ = layer.dedup;
    _ = layer.dedup_registry;
    _ = layer.verify_queue;
    _ = layer.verify_workers;
    _ = layer.ec_scheme;
    _ = sim.rs_mesh;
    _ = sim.gossipsub_transport;
    _ = sim.gossipsub_protocol;
    _ = sim.gossipsub_broadcast;
    _ = sim.gossipsub_interop;
    _ = sim.gossipsub_rpc_pb;
    _ = sim.gossipsub_rpc_host;
    _ = broadcast.engine;
    _ = broadcast.channel_rs;
    _ = broadcast.session_rs;
    _ = broadcast.observer;
    _ = broadcast.gossip;
    _ = broadcast.relay_async_verify;
}
