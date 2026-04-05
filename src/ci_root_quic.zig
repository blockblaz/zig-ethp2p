//! CI root: transport QUIC tests only (`zig build test-quic`).

test {
    _ = @import("transport/eth_ec_quic.zig");
}
