//! CI-only test root: mirrors ethp2p `go test -run 'TestNetwork/RS|TestNodeReconnection' ./sim/...`.
//! RS mesh covers `TestNetwork/RS`-style graphs plus partition/heal (`TestNodeReconnection` intent; that Go test is not on ethp2p `main` today).

test {
    _ = @import("sim/rs_mesh.zig");
}
