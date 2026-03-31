//! Min-heap for fair chunk dispatch (`broadcast/rs/emit.go`).

const std = @import("std");

pub const EmitEntry = struct {
    idx: usize,
    times: i32,
    sent: i32,
    priority: u32,
};

pub const PlannerError = error{ Empty, OutOfMemory };

pub const EmitPlanner = struct {
    id_to_pos: std.AutoHashMapUnmanaged(usize, usize) = .{},
    entries: std.ArrayListUnmanaged(EmitEntry) = .{},

    pub fn init(gpa: std.mem.Allocator) EmitPlanner {
        _ = gpa;
        return .{};
    }

    pub fn deinit(self: *EmitPlanner, gpa: std.mem.Allocator) void {
        self.entries.deinit(gpa);
        self.id_to_pos.deinit(gpa);
    }

    fn less(entries: []const EmitEntry, i: usize, j: usize) bool {
        const a = entries[i];
        const b = entries[j];
        if (a.times != b.times) return a.times < b.times;
        return a.priority < b.priority;
    }

    fn swap(self: *EmitPlanner, gpa: std.mem.Allocator, i: usize, j: usize) !void {
        const ei = self.entries.items[i].idx;
        const ej = self.entries.items[j].idx;
        std.mem.swap(EmitEntry, &self.entries.items[i], &self.entries.items[j]);
        try self.id_to_pos.put(gpa, ei, j);
        try self.id_to_pos.put(gpa, ej, i);
    }

    fn siftUp(self: *EmitPlanner, gpa: std.mem.Allocator, mut_i: usize) !void {
        var i = mut_i;
        while (i > 0) {
            const p = (i - 1) / 2;
            if (!less(self.entries.items, i, p)) break;
            try self.swap(gpa, i, p);
            i = p;
        }
    }

    fn siftDown(self: *EmitPlanner, gpa: std.mem.Allocator, start: usize, n: usize) !bool {
        var i = start;
        while (true) {
            const j1 = i * 2 + 1;
            if (j1 >= n) break;
            var j = j1;
            const j2 = j1 + 1;
            if (j2 < n and less(self.entries.items, j2, j1)) j = j2;
            if (!less(self.entries.items, j, i)) break;
            try self.swap(gpa, i, j);
            i = j;
        }
        return i != start;
    }

    fn fix(self: *EmitPlanner, gpa: std.mem.Allocator, i: usize) !void {
        const n = self.entries.items.len;
        if (n == 0) return;
        if (!(try self.siftDown(gpa, i, n))) {
            try self.siftUp(gpa, i);
        }
    }

    pub fn len(self: EmitPlanner) usize {
        return self.entries.items.len;
    }

    pub fn insert(self: *EmitPlanner, gpa: std.mem.Allocator, ec: EmitEntry) !void {
        if (self.id_to_pos.get(ec.idx)) |pos| {
            self.entries.items[pos] = ec;
            try self.fix(gpa, pos);
            return;
        }
        const pos = self.entries.items.len;
        try self.entries.append(gpa, ec);
        try self.id_to_pos.put(gpa, ec.idx, pos);
        try self.siftUp(gpa, pos);
    }

    pub fn top(self: EmitPlanner) ?EmitEntry {
        if (self.entries.items.len == 0) return null;
        return self.entries.items[0];
    }

    pub fn popFront(self: *EmitPlanner, gpa: std.mem.Allocator) PlannerError!EmitEntry {
        if (self.entries.items.len == 0) return error.Empty;
        if (self.entries.items.len == 1) {
            const last = self.entries.pop().?;
            _ = self.id_to_pos.remove(last.idx);
            return last;
        }
        const out = self.entries.items[0];
        _ = self.id_to_pos.remove(out.idx);
        const moved = self.entries.pop().?;
        self.entries.items[0] = moved;
        try self.id_to_pos.put(gpa, moved.idx, 0);
        _ = try self.siftDown(gpa, 0, self.entries.items.len);
        return out;
    }

    pub fn increment(self: *EmitPlanner, gpa: std.mem.Allocator, id: usize) !void {
        const idx = self.id_to_pos.get(id) orelse return;
        self.entries.items[idx].times += 1;
        try self.fix(gpa, idx);
    }

    pub fn contains(self: EmitPlanner, id: usize) bool {
        return self.id_to_pos.contains(id);
    }

    pub fn delete(self: *EmitPlanner, gpa: std.mem.Allocator, id: usize) !void {
        const idx = self.id_to_pos.get(id) orelse return;
        _ = self.id_to_pos.remove(self.entries.items[idx].idx);
        const last = self.entries.pop().?;
        if (idx < self.entries.items.len) {
            self.entries.items[idx] = last;
            try self.id_to_pos.put(gpa, last.idx, idx);
            try self.fix(gpa, idx);
        }
    }

    pub fn getSent(self: EmitPlanner, id: usize) ?i32 {
        const idx = self.id_to_pos.get(id) orelse return null;
        return self.entries.items[idx].sent;
    }

    pub fn addSent(self: *EmitPlanner, id: usize, delta: i32) void {
        const idx = self.id_to_pos.get(id) orelse return;
        self.entries.items[idx].sent += delta;
    }
};

test "emit planner order and increment" {
    const gpa = std.testing.allocator;
    var h = EmitPlanner.init(gpa);
    defer h.deinit(gpa);

    try h.insert(gpa, .{ .idx = 1, .times = 0, .sent = 0, .priority = 10 });
    try h.insert(gpa, .{ .idx = 2, .times = 0, .sent = 0, .priority = 5 });
    try h.insert(gpa, .{ .idx = 3, .times = 0, .sent = 0, .priority = 20 });

    const t = h.top().?;
    try std.testing.expectEqual(@as(usize, 2), t.idx);

    try h.increment(gpa, 2);
    const t2 = h.top().?;
    try std.testing.expectEqual(@as(usize, 1), t2.idx);

    _ = try h.popFront(gpa);
    const t3 = h.top().?;
    try std.testing.expectEqual(@as(usize, 3), t3.idx);
}

test "emit planner update insert" {
    const gpa = std.testing.allocator;
    var h = EmitPlanner.init(gpa);
    defer h.deinit(gpa);

    try h.insert(gpa, .{ .idx = 7, .times = 0, .sent = 0, .priority = 1 });
    try h.insert(gpa, .{ .idx = 7, .times = 2, .sent = 1, .priority = 99 });
    try std.testing.expectEqual(@as(usize, 1), h.len());
    try std.testing.expectEqual(@as(i32, 1), h.getSent(7).?);
}
