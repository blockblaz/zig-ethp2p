//! Zig implementation of [ethp2p](https://github.com/ethp2p/ethp2p) wire formats.
//! Behavior is validated against the reference Go stack; see `UPSTREAM.md`.

pub const wire = @import("wire/root.zig");

test {
    _ = wire;
}
