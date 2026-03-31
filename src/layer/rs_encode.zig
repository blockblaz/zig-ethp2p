//! Reed–Solomon parity encoding compatible with default `reedsolomon.New` from
//! [klauspost/reedsolomon](https://github.com/klauspost/reedsolomon) (Vandermonde × inverse(top)).

const std = @import("std");
const tables = @import("rs_galois_tables.zig");

pub const EncodeError = error{
    SingularMatrix,
    TooManyShards,
    InvalidLayout,
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
