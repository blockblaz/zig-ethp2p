//! CI-only test root: mirrors ethp2p `go test -run 'TestNetwork/Gossipsub' ./sim/...`.

test {
    _ = @import("sim/gossipsub_transport.zig");
    _ = @import("sim/gossipsub_protocol.zig");
    _ = @import("sim/gossipsub_broadcast.zig");
    _ = @import("sim/gossipsub_interop.zig");
    _ = @import("sim/gossipsub_rpc_pb.zig");
    _ = @import("sim/gossipsub_rpc_host.zig");
}
