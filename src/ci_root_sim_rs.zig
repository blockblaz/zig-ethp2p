//! CI-only test root: mirrors ethp2p `go test -run 'TestNetwork/RS|TestNodeReconnection' ./sim/...`.
//! Zig has no `TestNodeReconnection` analogue yet; RS abstract mesh covers `TestNetwork/RS`-style graphs.

test {
    _ = @import("sim/rs_mesh.zig");
}
