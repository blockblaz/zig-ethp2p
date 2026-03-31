const std = @import("std");

/// Bitset for RS routing (`broadcast/rs/bitmap.go`), backed by mutable bytes.
pub const Bitmap = struct {
    bytes: []u8,

    pub fn divCeil(n: usize, d: usize) usize {
        return (n + d - 1) / d;
    }

    pub fn initEmpty(allocator: std.mem.Allocator, n: usize) !Bitmap {
        const nbytes = divCeil(n, 8);
        const buf = try allocator.alloc(u8, nbytes);
        @memset(buf, 0);
        return .{ .bytes = buf };
    }

    pub fn initAllOnes(allocator: std.mem.Allocator, n: usize) !Bitmap {
        var b = try initEmpty(allocator, n);
        for (0..n) |i| b.set(i);
        return b;
    }

    pub fn deinit(self: Bitmap, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
    }

    pub fn bitCapacity(self: Bitmap) usize {
        return self.bytes.len * 8;
    }

    pub fn set(self: Bitmap, index: usize) void {
        if (index >= self.bitCapacity()) return;
        self.bytes[index / 8] |= @as(u8, 1) << @intCast(index % 8);
    }

    pub fn get(self: Bitmap, index: usize) bool {
        if (index >= self.bitCapacity()) return false;
        return self.bytes[index / 8] & (@as(u8, 1) << @intCast(index % 8)) != 0;
    }

    pub fn unset(self: Bitmap, index: usize) void {
        if (index >= self.bitCapacity()) return;
        self.bytes[index / 8] &= ~(@as(u8, 1) << @intCast(index % 8));
    }

    pub fn onesCount(self: Bitmap) usize {
        var count: usize = 0;
        for (self.bytes) |b| count += @popCount(b);
        return count;
    }

    pub fn isZero(self: Bitmap) bool {
        for (self.bytes) |b| if (b != 0) return false;
        return true;
    }

    pub fn clone(self: Bitmap, allocator: std.mem.Allocator) !Bitmap {
        const c = try allocator.dupe(u8, self.bytes);
        return .{ .bytes = c };
    }

    pub fn orInPlace(self: Bitmap, other: Bitmap) void {
        const n = @min(self.bytes.len, other.bytes.len);
        for (0..n) |i| self.bytes[i] |= other.bytes[i];
    }

    pub fn andInPlace(self: Bitmap, other: Bitmap) void {
        const n = @min(self.bytes.len, other.bytes.len);
        for (0..n) |i| self.bytes[i] &= other.bytes[i];
    }

    pub fn marshal(self: Bitmap, allocator: std.mem.Allocator) ![]u8 {
        return allocator.dupe(u8, self.bytes);
    }

    pub fn unmarshalOwned(allocator: std.mem.Allocator, data: []const u8) !Bitmap {
        const b = try allocator.dupe(u8, data);
        return .{ .bytes = b };
    }
};

test "bitmap set get ones" {
    const gpa = std.testing.allocator;
    var b = try Bitmap.initEmpty(gpa, 10);
    defer b.deinit(gpa);
    b.set(0);
    b.set(9);
    try std.testing.expect(b.get(0));
    try std.testing.expect(!b.get(1));
    try std.testing.expect(b.get(9));
    try std.testing.expectEqual(@as(usize, 2), b.onesCount());
}

test "bitmap all ones" {
    const gpa = std.testing.allocator;
    var b = try Bitmap.initAllOnes(gpa, 5);
    defer b.deinit(gpa);
    for (0..5) |i| try std.testing.expect(b.get(i));
    try std.testing.expect(!b.get(5));
}
