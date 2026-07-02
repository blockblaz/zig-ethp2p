const std = @import("std");

/// Matches `ethp2p.protocol.Protocol` in `protocol.proto` (numeric values).
///
/// On the wire, the reference stack does **not** send a protobuf `Selector`
/// message. It sends a single byte equal to the enum value; see
/// `protocol.WriteSelector` / `ReadSelector` in github.com/ethp2p/ethp2p.
pub const Protocol = enum(u8) {
    unspecified = 0,
    bcast = 1,
    sess = 2,
    chunk = 3,
    _,
};

pub const ErrUnspecified = error{ProtocolUnspecified};

/// Matches `protocol.WriteSelector`.
pub fn writeSelectorByte(writer: *std.Io.Writer, p: Protocol) std.Io.Writer.Error!void {
    try writer.writeAll(&.{@intFromEnum(p)});
}

/// Matches `protocol.ReadSelector` (rejects `PROTOCOL_UNSPECIFIED`).
pub fn readSelectorByte(reader: *std.Io.Reader) !Protocol {
    var b: [1]u8 = undefined;
    try reader.readSliceAll(&b);
    if (b[0] == 0) return error.ProtocolUnspecified;
    return @enumFromInt(b[0]);
}

test "selector byte matches reference (BCAST = 0x01)" {
    var aw = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer aw.deinit();
    {
        try writeSelectorByte(&aw.writer, .bcast);
    }
    try std.testing.expectEqualSlices(u8, &.{0x01}, aw.written());

    var fbs = std.Io.Reader.fixed(aw.written());
    const p = try readSelectorByte(&fbs);
    try std.testing.expectEqual(Protocol.bcast, p);
}

test "readSelectorByte rejects unspecified" {
    var buf = [_]u8{0};
    var fbs = std.Io.Reader.fixed(&buf);
    try std.testing.expectError(error.ProtocolUnspecified, readSelectorByte(&fbs));
}
