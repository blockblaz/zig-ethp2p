//! Cross-session chunk dedup: first claim wins for `(channel_id, message_id, chunk_index)`.
//! Complements per-strategy `takeChunk` redundancy (same index already stored).

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const DedupRegistry = struct {
    seen: std.StringHashMapUnmanaged(void) = .{},

    pub fn deinit(self: *DedupRegistry, allocator: Allocator) void {
        var it = self.seen.keyIterator();
        while (it.next()) |k| {
            allocator.free(k.*);
        }
        self.seen.deinit(allocator);
    }

    /// `true` if this triple was not seen before (inserted). `false` if duplicate.
    pub fn claim(
        self: *DedupRegistry,
        allocator: Allocator,
        channel_id: []const u8,
        message_id: []const u8,
        chunk_index: i32,
    ) Allocator.Error!bool {
        const key = try makeKey(allocator, channel_id, message_id, chunk_index);
        errdefer allocator.free(key);
        if (self.seen.contains(key)) {
            allocator.free(key);
            return false;
        }
        try self.seen.put(allocator, key, {});
        return true;
    }

    /// Drop every key for `message_id` on `channel_id` (e.g. after decode / session end).
    pub fn forgetMessage(
        self: *DedupRegistry,
        allocator: Allocator,
        channel_id: []const u8,
        message_id: []const u8,
    ) void {
        const prefix = makePrefixLen(channel_id, message_id);
        var to_remove: std.ArrayListUnmanaged([]const u8) = .{};
        defer to_remove.deinit(allocator);

        var it = self.seen.iterator();
        while (it.next()) |ent| {
            if (keyMatchesPrefix(ent.key_ptr.*, channel_id, message_id, prefix)) {
                to_remove.append(allocator, ent.key_ptr.*) catch return;
            }
        }
        for (to_remove.items) |k| {
            if (self.seen.fetchRemove(k)) |kv| {
                allocator.free(kv.key);
            }
        }
    }
};

fn makeKey(allocator: Allocator, ch: []const u8, msg: []const u8, idx: i32) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}\x00{s}\x00{d}", .{ ch, msg, idx });
}

fn makePrefixLen(ch: []const u8, msg: []const u8) usize {
    return ch.len + 1 + msg.len + 1;
}

fn keyMatchesPrefix(key: []const u8, ch: []const u8, msg: []const u8, prefix_len: usize) bool {
    if (key.len < prefix_len + 1) return false;
    if (!std.mem.startsWith(u8, key, ch)) return false;
    if (key[ch.len] != 0) return false;
    const rest = key[ch.len + 1 ..];
    if (!std.mem.startsWith(u8, rest, msg)) return false;
    if (rest[msg.len] != 0) return false;
    return true;
}

test "dedup registry claim and forget" {
    const gpa = std.testing.allocator;
    var reg: DedupRegistry = .{};
    defer reg.deinit(gpa);

    try std.testing.expect(try reg.claim(gpa, "ch", "m1", 0));
    try std.testing.expect(!try reg.claim(gpa, "ch", "m1", 0));
    try std.testing.expect(try reg.claim(gpa, "ch", "m1", 1));
    try std.testing.expect(try reg.claim(gpa, "ch", "m2", 0));

    reg.forgetMessage(gpa, "ch", "m1");
    try std.testing.expect(try reg.claim(gpa, "ch", "m1", 0));
    try std.testing.expect(!try reg.claim(gpa, "ch", "m2", 0));
}
