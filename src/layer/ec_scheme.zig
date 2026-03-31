//! Erasure-coding scheme discriminator for the broadcast channel (ethp2p `broadcast.Scheme` / [#14](https://github.com/ch4r10t33r/zig-ethp2p/issues/14)).
//!
//! Today only Reed–Solomon is implemented (`layer.rs_strategy`, `layer.rs_encode`). RLNC and other
//! schemes need preamble / chunk-ident wire shapes and strategy implementations once the spec pins them.

const std = @import("std");

/// Kind of EC used on a channel. Numeric values are reserved for future on-the-wire use; only
/// `reed_solomon` is implemented.
pub const EcSchemeKind = enum(u8) {
    reed_solomon = 0,
    /// Random linear network coding — not implemented.
    rlnc = 1,

    /// Stable name matching ethp2p `rs.NewScheme` → `Scheme.Name` (`"reed-solomon"`).
    pub fn wireName(self: EcSchemeKind) []const u8 {
        return switch (self) {
            .reed_solomon => "reed-solomon",
            .rlnc => "rlnc",
        };
    }

    /// Whether `zig-ethp2p` can build origin/relay strategy and run decode for this kind.
    pub fn isImplemented(self: EcSchemeKind) bool {
        return self == .reed_solomon;
    }
};

test "reed-solomon wire name matches ethp2p rs.NewScheme" {
    try std.testing.expectEqualStrings("reed-solomon", EcSchemeKind.reed_solomon.wireName());
    try std.testing.expect(EcSchemeKind.reed_solomon.isImplemented());
    try std.testing.expect(!EcSchemeKind.rlnc.isImplemented());
}
