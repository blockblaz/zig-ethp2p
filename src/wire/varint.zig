const std = @import("std");

pub fn append(dst: *std.ArrayList(u8), gpa: std.mem.Allocator, value: u64) std.mem.Allocator.Error!void {
    var v = value;
    while (v >= 0x80) {
        try dst.append(gpa, @as(u8, @truncate(v & 0x7f | 0x80)));
        v >>= 7;
    }
    try dst.append(gpa, @as(u8, @truncate(v)));
}

pub const DecodeError = error{ Truncated, Overflow, TooLong };

/// Decodes a protobuf varint; returns value and new offset.
pub fn decode(buf: []const u8, offset: *usize) DecodeError!u64 {
    var shift: u6 = 0;
    var result: u64 = 0;
    var i = offset.*;
    while (i < buf.len) : (i += 1) {
        const b = buf[i];
        if (shift == 63 and b > 1) return error.Overflow;
        result |= @as(u64, b & 0x7f) << shift;
        if (b & 0x80 == 0) {
            offset.* = i + 1;
            return result;
        }
        shift += 7;
        if (shift > 63) return error.TooLong;
    }
    return error.Truncated;
}

/// Decodes a protobuf `int32` for non-negative values (sufficient for RS preamble counts).
pub fn decodeNonNegativeI32(buf: []const u8, offset: *usize) DecodeError!i32 {
    const u = try decode(buf, offset);
    if (u > @as(u64, @intCast(std.math.maxInt(i32)))) return error.Overflow;
    return @intCast(u);
}
