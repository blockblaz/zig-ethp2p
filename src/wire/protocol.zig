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
pub fn writeSelectorByte(writer: anytype, p: Protocol) @TypeOf(writer).Error!void {
    try writer.writeAll(&.{@intFromEnum(p)});
}

/// Matches `protocol.ReadSelector` (rejects `PROTOCOL_UNSPECIFIED`).
pub fn readSelectorByte(reader: anytype) !Protocol {
    var b: [1]u8 = undefined;
    try reader.readNoEof(&b);
    if (b[0] == 0) return error.ProtocolUnspecified;
    return @enumFromInt(b[0]);
}

test "selector byte matches reference (BCAST = 0x01)" {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(std.testing.allocator);
    {
        const w = list.writer(std.testing.allocator);
        try writeSelectorByte(w, .bcast);
    }
    try std.testing.expectEqualSlices(u8, &.{0x01}, list.items);

    var fbs = std.io.fixedBufferStream(list.items);
    const p = try readSelectorByte(fbs.reader());
    try std.testing.expectEqual(Protocol.bcast, p);
}

test "readSelectorByte rejects unspecified" {
    var buf = [_]u8{0};
    var fbs = std.io.fixedBufferStream(&buf);
    try std.testing.expectError(error.ProtocolUnspecified, readSelectorByte(fbs.reader()));
}
