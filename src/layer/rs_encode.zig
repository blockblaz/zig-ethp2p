//! Reed–Solomon parity encoding compatible with default `reedsolomon.New` from
//! [klauspost/reedsolomon](https://github.com/klauspost/reedsolomon) (Vandermonde × inverse(top)).

const std = @import("std");
const tables = @import("rs_galois_tables.zig");

pub const EncodeError = error{
    SingularMatrix,
    TooManyShards,
    TooFewShards,
    InvalidLayout,
    ShardSizeMismatch,
    HashMismatch,
    InvalidMessageLength,
} || std.mem.Allocator.Error;

fn galAdd(a: u8, b: u8) u8 {
    return a ^ b;
}

fn galMul(a: u8, b: u8) u8 {
    if (a == 0 or b == 0) return 0;
    const la: u32 = tables.log_table[a];
    const lb: u32 = tables.log_table[b];
    var s = la + lb;
    while (s >= 255) s -= 255;
    return tables.exp_table[@intCast(s)];
}

fn galOneOver(a: u8) u8 {
    std.debug.assert(a != 0);
    const log_result: u8 = tables.log_table[a] ^ 255;
    return tables.exp_table[log_result];
}

fn galExp(base: u8, power: usize) u8 {
    if (power == 0) return 1;
    if (base == 0) return 0;
    const log_a: u32 = tables.log_table[base];
    var log_result: u32 = log_a * @as(u32, @intCast(power));
    while (log_result >= 255) log_result -= 255;
    return tables.exp_table[@intCast(log_result)];
}

fn matrixAlloc(allocator: std.mem.Allocator, rows: usize, cols: usize) EncodeError![][]u8 {
    const m = try allocator.alloc([]u8, rows);
    errdefer allocator.free(m);
    var i: usize = 0;
    errdefer {
        for (m[0..i]) |row| allocator.free(row);
        allocator.free(m);
    }
    while (i < rows) : (i += 1) {
        const row = try allocator.alloc(u8, cols);
        @memset(row, 0);
        m[i] = row;
    }
    return m;
}

fn matrixFree(allocator: std.mem.Allocator, m: [][]u8) void {
    for (m) |row| allocator.free(row);
    allocator.free(m);
}

fn vandermonde(allocator: std.mem.Allocator, rows: usize, cols: usize) EncodeError![][]u8 {
    const m = try matrixAlloc(allocator, rows, cols);
    for (0..rows) |r| {
        const rb: u8 = @intCast(r);
        for (0..cols) |c| {
            m[r][c] = galExp(rb, c);
        }
    }
    return m;
}

fn matrixMultiply(allocator: std.mem.Allocator, left: [][]const u8, right: [][]const u8) EncodeError![][]u8 {
    const nrows = left.len;
    const nmid = left[0].len;
    std.debug.assert(right.len == nmid);
    const ncols = right[0].len;
    const out = try matrixAlloc(allocator, nrows, ncols);
    for (0..nrows) |r| {
        for (0..ncols) |c| {
            var acc: u8 = 0;
            for (0..nmid) |k| {
                acc = galAdd(acc, galMul(left[r][k], right[k][c]));
            }
            out[r][c] = acc;
        }
    }
    return out;
}

fn subMatrix(
    allocator: std.mem.Allocator,
    m: [][]const u8,
    rmin: usize,
    cmin: usize,
    rmax: usize,
    cmax: usize,
) EncodeError![][]u8 {
    const rows = rmax - rmin;
    const cols = cmax - cmin;
    const out = try matrixAlloc(allocator, rows, cols);
    for (0..rows) |r| {
        @memcpy(out[r], m[rmin + r][cmin .. cmin + cols]);
    }
    return out;
}

fn identityMatrix(allocator: std.mem.Allocator, size: usize) EncodeError![][]u8 {
    const m = try matrixAlloc(allocator, size, size);
    for (0..size) |i| m[i][i] = 1;
    return m;
}

fn augment(allocator: std.mem.Allocator, left: [][]const u8, right: [][]const u8) EncodeError![][]u8 {
    std.debug.assert(left.len == right.len);
    const rows = left.len;
    const lcols = left[0].len;
    const rcols = right[0].len;
    const out = try matrixAlloc(allocator, rows, lcols + rcols);
    for (0..rows) |r| {
        @memcpy(out[r][0..lcols], left[r]);
        @memcpy(out[r][lcols..][0..rcols], right[r]);
    }
    return out;
}

fn gaussianElimination(m: [][]u8) EncodeError!void {
    const rows = m.len;
    const columns = m[0].len;

    for (0..rows) |r| {
        if (m[r][r] == 0) {
            var found: ?usize = null;
            var row_below = r + 1;
            while (row_below < rows) : (row_below += 1) {
                if (m[row_below][r] != 0) {
                    found = row_below;
                    break;
                }
            }
            if (found) |rb| {
                std.mem.swap([]u8, &m[r], &m[rb]);
            }
        }
        if (m[r][r] == 0) return error.SingularMatrix;

        if (m[r][r] != 1) {
            const scale = galOneOver(m[r][r]);
            for (0..columns) |c| m[r][c] = galMul(m[r][c], scale);
        }

        var row_below = r + 1;
        while (row_below < rows) : (row_below += 1) {
            if (m[row_below][r] != 0) {
                const scale = m[row_below][r];
                for (0..columns) |c| {
                    m[row_below][c] = galAdd(m[row_below][c], galMul(scale, m[r][c]));
                }
            }
        }
    }

    for (0..rows) |d| {
        for (0..d) |row_above| {
            if (m[row_above][d] != 0) {
                const scale = m[row_above][d];
                for (0..columns) |c| {
                    m[row_above][c] = galAdd(m[row_above][c], galMul(scale, m[d][c]));
                }
            }
        }
    }
}

fn matrixInvert(allocator: std.mem.Allocator, m_in: [][]const u8) EncodeError![][]u8 {
    const size = m_in.len;
    std.debug.assert(size == m_in[0].len);

    const id = try identityMatrix(allocator, size);
    defer matrixFree(allocator, id);

    const work = try augment(allocator, m_in, id);
    defer matrixFree(allocator, work);

    try gaussianElimination(work);
    return subMatrix(allocator, work, 0, size, size, size * 2);
}

fn buildEncodeMatrix(allocator: std.mem.Allocator, data_shards: usize, total_shards: usize) EncodeError![][]u8 {
    const vm = try vandermonde(allocator, total_shards, data_shards);
    defer matrixFree(allocator, vm);

    const top = try subMatrix(allocator, vm, 0, 0, data_shards, data_shards);
    defer matrixFree(allocator, top);

    const top_inv = try matrixInvert(allocator, top);
    defer matrixFree(allocator, top_inv);

    return matrixMultiply(allocator, vm, top_inv);
}

/// `matrix_rows[i]` dotted with `inputs[j][b]` over `j` → `outputs[i][b]` (GF XOR sum).
fn codeSomeShards(
    matrix_rows: []const []const u8,
    inputs: []const []const u8,
    outputs: [][]u8,
    byte_count: usize,
) void {
    for (matrix_rows, outputs) |row, out| {
        for (0..byte_count) |b| {
            var acc: u8 = 0;
            for (inputs, 0..) |inp, j| {
                acc = galAdd(acc, galMul(row[j], inp[b]));
            }
            out[b] = acc;
        }
    }
}

fn firstShardLen(shards: []const []const u8) ?usize {
    for (shards) |s| {
        if (s.len != 0) return s.len;
    }
    return null;
}

fn countPresent(shards: []const []const u8) usize {
    var n: usize = 0;
    for (shards) |s| {
        if (s.len != 0) n += 1;
    }
    return n;
}

fn countDataPresent(shards: []const []const u8, k: usize) usize {
    var n: usize = 0;
    const lim = @min(k, shards.len);
    for (0..lim) |i| {
        if (shards[i].len != 0) n += 1;
    }
    return n;
}

/// Stateful encoder/decoder matching [klauspost/reedsolomon] `New` + `Encode` + `Reconstruct` / `ReconstructData`.
pub const ReedSolomon = struct {
    allocator: std.mem.Allocator,
    data_shards: usize,
    parity_shards: usize,
    /// Full encoding matrix: `total × data_shards`.
    encode_matrix: [][]u8,
    /// Parity row views: `parity_shards` rows, each length `data_shards` (owned copies).
    parity_rows: [][]u8,

    pub fn init(allocator: std.mem.Allocator, data_shards: usize, parity_shards: usize) EncodeError!ReedSolomon {
        if (data_shards == 0) return error.InvalidLayout;
        const total = data_shards + parity_shards;
        if (total > 256) return error.TooManyShards;

        const m = try buildEncodeMatrix(allocator, data_shards, total);
        errdefer matrixFree(allocator, m);

        const p_rows = try allocator.alloc([]u8, parity_shards);
        errdefer allocator.free(p_rows);
        var pi: usize = 0;
        errdefer {
            for (p_rows[0..pi]) |row| allocator.free(row);
            allocator.free(p_rows);
        }
        while (pi < parity_shards) : (pi += 1) {
            p_rows[pi] = try allocator.dupe(u8, m[data_shards + pi]);
        }

        return .{
            .allocator = allocator,
            .data_shards = data_shards,
            .parity_shards = parity_shards,
            .encode_matrix = m,
            .parity_rows = p_rows,
        };
    }

    pub fn deinit(self: *ReedSolomon) void {
        matrixFree(self.allocator, self.encode_matrix);
        for (self.parity_rows) |row| self.allocator.free(row);
        self.allocator.free(self.parity_rows);
    }

    pub fn totalShards(self: ReedSolomon) usize {
        return self.data_shards + self.parity_shards;
    }

    /// Fills parity shards from data shards (same as klauspost `Encode`).
    pub fn encode(self: ReedSolomon, shards: [][]u8, shard_len: usize) void {
        const k = self.data_shards;
        const total = self.totalShards();
        for (k..total) |row| {
            for (0..shard_len) |col| {
                var acc: u8 = 0;
                for (0..k) |d| {
                    acc = galAdd(acc, galMul(self.encode_matrix[row][d], shards[d][col]));
                }
                shards[row][col] = acc;
            }
        }
    }

    /// Missing shards have `len == 0`. Allocates replacement buffers via `allocator` for missing rows.
    pub fn reconstruct(self: *ReedSolomon, scratch_alloc: std.mem.Allocator, shards: [][]u8, shard_len: usize) EncodeError!void {
        return self.reconstructInternal(scratch_alloc, shards, shard_len, false);
    }

    pub fn reconstructData(self: *ReedSolomon, scratch_alloc: std.mem.Allocator, shards: [][]u8, shard_len: usize) EncodeError!void {
        return self.reconstructInternal(scratch_alloc, shards, shard_len, true);
    }

    fn reconstructInternal(
        self: *ReedSolomon,
        scratch_alloc: std.mem.Allocator,
        shards: [][]u8,
        shard_len: usize,
        data_only: bool,
    ) EncodeError!void {
        const k = self.data_shards;
        const total = self.totalShards();
        if (shards.len < total) return error.InvalidLayout;

        const sz = firstShardLen(shards) orelse return error.TooFewShards;
        if (sz != shard_len) return error.ShardSizeMismatch;
        for (shards) |s| {
            if (s.len != 0 and s.len != shard_len) return error.ShardSizeMismatch;
        }

        if (countPresent(shards) == total) return;
        if (countPresent(shards) < k) return error.TooFewShards;

        const data_pres = countDataPresent(shards, k);
        if (data_only and data_pres == k) return;

        const need_decode_data = data_pres < k;
        if (need_decode_data) {
            var valid_indices: [256]usize = undefined;
            var sub_inputs: [256][]const u8 = undefined;
            var sub_row: usize = 0;
            var matrix_row: usize = 0;
            while (matrix_row < total and sub_row < k) : (matrix_row += 1) {
                if (shards[matrix_row].len != 0) {
                    valid_indices[sub_row] = matrix_row;
                    sub_inputs[sub_row] = shards[matrix_row][0..shard_len];
                    sub_row += 1;
                }
            }
            if (sub_row < k) return error.TooFewShards;

            const sub_matrix = try matrixAlloc(scratch_alloc, k, k);
            defer matrixFree(scratch_alloc, sub_matrix);
            for (0..k) |r| {
                for (0..k) |c| {
                    sub_matrix[r][c] = self.encode_matrix[valid_indices[r]][c];
                }
            }

            const decode_matrix = try matrixInvert(scratch_alloc, sub_matrix);
            defer matrixFree(scratch_alloc, decode_matrix);

            var matrix_row_bufs: [256][]const u8 = undefined;
            var out_row_bufs: [256][]u8 = undefined;
            var out_n: usize = 0;

            for (0..k) |i_shard| {
                if (shards[i_shard].len != 0) continue;
                const buf = try scratch_alloc.alloc(u8, shard_len);
                shards[i_shard] = buf;
                matrix_row_bufs[out_n] = decode_matrix[i_shard][0..k];
                out_row_bufs[out_n] = shards[i_shard][0..shard_len];
                out_n += 1;
            }
            if (out_n > 0) {
                codeSomeShards(matrix_row_bufs[0..out_n], sub_inputs[0..k], out_row_bufs[0..out_n], shard_len);
            }
        }

        if (data_only) return;

        var p_matrix_row_bufs: [256][]const u8 = undefined;
        var p_out_bufs: [256][]u8 = undefined;
        var p_out_n: usize = 0;
        for (k..total) |i_shard| {
            if (shards[i_shard].len != 0) continue;
            const buf = try scratch_alloc.alloc(u8, shard_len);
            shards[i_shard] = buf;
            p_matrix_row_bufs[p_out_n] = self.parity_rows[i_shard - k];
            p_out_bufs[p_out_n] = shards[i_shard][0..shard_len];
            p_out_n += 1;
        }
        if (p_out_n > 0) {
            var data_ins: [256][]const u8 = undefined;
            for (0..k) |d| data_ins[d] = shards[d][0..shard_len];
            codeSomeShards(p_matrix_row_bufs[0..p_out_n], data_ins[0..k], p_out_bufs[0..p_out_n], shard_len);
        }
    }
};

/// Concatenate first `data_shards` shards (each `shard_len`), trim to `message_length`, verify SHA-256.
/// Matches ethp2p `(*strategy).tryDecode` after `ReconstructData`.
pub fn decodeMessage(
    allocator: std.mem.Allocator,
    data_shards: usize,
    parity_shards: usize,
    shards: [][]u8,
    shard_len: usize,
    message_length: usize,
    expected_message_hash: [32]u8,
) EncodeError![]u8 {
    if (message_length == 0) return error.InvalidMessageLength;
    var rs = try ReedSolomon.init(allocator, data_shards, parity_shards);
    defer rs.deinit();
    try rs.reconstructData(allocator, shards, shard_len);

    const cat_len = data_shards * shard_len;
    if (message_length > cat_len) return error.InvalidMessageLength;

    var concat = try allocator.alloc(u8, cat_len);
    defer allocator.free(concat);
    var off: usize = 0;
    for (0..data_shards) |i| {
        @memcpy(concat[off..][0..shard_len], shards[i][0..shard_len]);
        off += shard_len;
    }

    const msg = concat[0..message_length];
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
    if (!std.mem.eql(u8, &digest, &expected_message_hash)) return error.HashMismatch;

    return try allocator.dupe(u8, msg);
}

/// Overwrites `shards[data_shards..]` using the first `data_shards` rows as inputs.
/// Each shard slice must be at least `shard_len` bytes; only the first `shard_len` are used.
pub fn encodeParity(
    allocator: std.mem.Allocator,
    data_shards: usize,
    parity_shards: usize,
    shards: [][]u8,
    shard_len: usize,
) EncodeError!void {
    if (data_shards == 0) return error.InvalidLayout;
    const total = data_shards + parity_shards;
    if (total > 256) return error.TooManyShards;
    if (shards.len < total) return error.InvalidLayout;
    if (parity_shards == 0) return;

    const m = try buildEncodeMatrix(allocator, data_shards, total);
    defer matrixFree(allocator, m);

    for (data_shards..total) |row| {
        for (0..shard_len) |col| {
            var acc: u8 = 0;
            for (0..data_shards) |d| {
                acc = galAdd(acc, galMul(m[row][d], shards[d][col]));
            }
            shards[row][col] = acc;
        }
    }
}

test "encode parity matches klauspost New(4,2)" {
    const gpa = std.testing.allocator;
    const k: usize = 4;
    const p: usize = 2;
    const total = k + p;
    const shard_len: usize = 8;

    var storage: [6][8]u8 = undefined;
    var shards: [6][]u8 = undefined;
    for (0..k) |i| {
        for (0..shard_len) |j| storage[i][j] = @intCast(i * 8 + j);
        shards[i] = &storage[i];
    }
    for (k..total) |i| {
        @memset(&storage[i], 0);
        shards[i] = &storage[i];
    }

    try encodeParity(gpa, k, p, &shards, shard_len);

    const want4 = [_]u8{ 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27 };
    const want5 = [_]u8{ 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f };
    try std.testing.expectEqualSlices(u8, &want4, shards[4]);
    try std.testing.expectEqualSlices(u8, &want5, shards[5]);
}

test "ReedSolomon encode reconstructData one missing data shard" {
    const gpa = std.testing.allocator;
    const k: usize = 4;
    const p: usize = 2;
    const total = k + p;
    const shard_len: usize = 8;

    var storage: [6][8]u8 = undefined;
    var shards: [6][]u8 = undefined;
    for (0..k) |i| {
        for (0..shard_len) |j| storage[i][j] = @intCast(i * 8 + j);
        shards[i] = &storage[i];
    }
    for (k..total) |i| {
        @memset(&storage[i], 0);
        shards[i] = &storage[i];
    }

    var rs = try ReedSolomon.init(gpa, k, p);
    defer rs.deinit();
    rs.encode(&shards, shard_len);

    const saved: [8]u8 = storage[1];
    shards[1] = &[_]u8{};

    try rs.reconstructData(gpa, &shards, shard_len);
    try std.testing.expectEqualSlices(u8, &saved, shards[1]);
}

test "decodeMessage matches tryDecode path" {
    const gpa = std.testing.allocator;
    const k: usize = 4;
    const p: usize = 2;
    const msg = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

    const layout = @import("rs_init.zig").initPreamble(
        .{
            .data_shards = @intCast(k),
            .parity_shards = @intCast(p),
            .chunk_len = 0,
            .bitmap_threshold = 0,
            .forward_multiplier = 4,
            .disable_bitmap = false,
        },
        msg.len,
    );
    const dc = @as(usize, @intCast(layout.data_chunks));
    const pc = @as(usize, @intCast(layout.parity_chunks));
    const tot = dc + pc;
    const cl = layout.chunk_len;

    const slab_len = dc * cl;
    var slab = try gpa.alloc(u8, slab_len);
    defer gpa.free(slab);
    @memcpy(slab[0..msg.len], &msg);
    @memset(slab[msg.len..slab_len], 0);

    var shard_bufs: [32][]u8 = undefined;
    for (0..dc) |i| {
        shard_bufs[i] = slab[i * cl ..][0..cl];
    }
    for (dc..tot) |i| {
        shard_bufs[i] = try gpa.alloc(u8, cl);
    }
    defer {
        for (dc..tot) |i| gpa.free(shard_bufs[i]);
    }

    var rs = try ReedSolomon.init(gpa, dc, pc);
    defer rs.deinit();
    rs.encode(shard_bufs[0..tot], cl);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&msg, &digest, .{});

    var work = try gpa.alloc([]u8, tot);
    defer gpa.free(work);
    defer {
        for (work) |s| if (s.len != 0) gpa.free(s);
    }
    for (0..tot) |i| {
        if (i == 0 or i == 1) {
            work[i] = &[_]u8{};
        } else {
            work[i] = try gpa.dupe(u8, shard_bufs[i]);
        }
    }

    const out = try decodeMessage(gpa, dc, pc, work, cl, msg.len, digest);
    defer gpa.free(out);
    try std.testing.expectEqualSlices(u8, &msg, out);
}
