//! Multiformats / protobuf unsigned-varint, re-exported from the shared
//! [`zig-varint`](https://github.com/ch4r10t33r/zig-varint) codec (issue #57) —
//! the same package zquic and zig-libp2p already adopted.
//!
//! Thin back-compat wrapper so existing call sites keep the in-tree names
//! (`append`, `decode`, `decodeNonNegativeI32`, `DecodeError`). The cursor
//! decoders use the *relaxed* variant to preserve the previous in-tree
//! decoder's tolerance of non-minimal encodings.

const std = @import("std");
const unsigned = @import("zig_varint").unsigned;

pub const DecodeError = unsigned.DecodeError;

/// Appends `value` to `dst` as an unsigned-varint.
pub const append = unsigned.append;

/// Decodes an unsigned-varint at `offset`, advancing it past the value.
pub fn decode(buf: []const u8, offset: *usize) DecodeError!u64 {
    return unsigned.decodeAtRelaxed(buf, offset);
}

/// Decodes a non-negative protobuf `int32` (sufficient for RS preamble counts).
pub fn decodeNonNegativeI32(buf: []const u8, offset: *usize) DecodeError!i32 {
    const u = try decode(buf, offset);
    if (u > @as(u64, @intCast(std.math.maxInt(i32)))) return error.Overflow;
    return @intCast(u);
}
