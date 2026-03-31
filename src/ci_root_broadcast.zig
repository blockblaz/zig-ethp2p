//! CI-only test root: mirrors ethp2p `go test ./broadcast/...` (wire + layer + all `broadcast/`; no `sim/`).
//! When adding `broadcast/` modules or layer test files, keep this aligned with `src/root.zig` (excluding `sim`).

test {
    _ = @import("wire/root.zig");
    _ = @import("layer/bitmap.zig");
    _ = @import("layer/dedup.zig");
    _ = @import("layer/dedup_registry.zig");
    _ = @import("layer/emit_planner.zig");
    _ = @import("layer/rs_encode.zig");
    _ = @import("layer/rs_init.zig");
    _ = @import("layer/rs_strategy.zig");
    _ = @import("layer/verify_queue.zig");
    _ = @import("layer/verify_workers.zig");
    _ = @import("broadcast/observer.zig");
    _ = @import("broadcast/engine.zig");
    _ = @import("broadcast/channel_rs.zig");
    _ = @import("broadcast/session_rs.zig");
    _ = @import("broadcast/gossip.zig");
    _ = @import("broadcast/relay_async_verify.zig");
}
