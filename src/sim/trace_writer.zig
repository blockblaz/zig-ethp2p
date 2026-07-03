//! Broadcast trace writer — compact NDJSON `.bctrace` output.
//! Like-for-like port of [sim/trace_writer.go](https://github.com/ethp2p/ethp2p/blob/main/sim/trace_writer.go):
//! a header line, one JSON-array tuple per event, and a footer line carrying a
//! coarse time index. Byte layout, field order, event-row shape, and the 100 ms
//! index cadence match the Go reference; golden-byte tests lock this down.
//!
//! Adaptations (documented, not omissions):
//!   * Output is accumulated into an owned byte buffer (`bytes()`), matching this
//!     repo's allocate-bytes style, instead of Go's `io.Writer` + `bufio` sink.
//!     The observable bytes are identical; buffering is an internal detail.
//!   * `t0`, `topology`, and `config` enter as caller-provided raw values
//!     (an RFC3339 string and raw JSON slices) because the Zig sim has no
//!     `time.Time` or reflective `json.Marshal`. Go's `TracingObserver`
//!     (`sim/trace_observer.go`), which maps broadcast events to the event
//!     codes below, lands once the `Observer` interface exists (issue #58).

const std = @import("std");

const Allocator = std.mem.Allocator;

/// Go `defaultIndexInterval` — 100 ms expressed in microseconds.
pub const default_index_interval_us: i64 = 100_000;

/// Trace format version written into the header (`traceHeader.V`).
pub const trace_version: i64 = 1;

/// Event codes emitted by Go `TracingObserver` (`sim/trace_observer.go`).
/// Exposed for the observer port (issue #58) and for readers of the trace.
pub const event = struct {
    pub const peer_handshook = "ph";
    pub const peer_subscribed = "ps";
    pub const peer_unsubscribed = "pu";
    pub const peer_gone = "pg";
    pub const session_started = "ss";
    pub const session_decoded = "sd";
    pub const session_disposed = "sx";
    pub const chunk_sent = "cs";
    pub const chunk_rcvd = "cr";
    pub const chunk_error = "ce";
    pub const routing_update = "ru";
    pub const preamble_opened = "po";
    pub const strategy_progress = "sp";
};

/// One positional event argument. Go passes `...any`; the reference only ever
/// emits integers and strings (peer/channel/message ids, byte counts, verdicts).
pub const Arg = union(enum) {
    int: i64,
    str: []const u8,
};

/// Optional header fields (Go `TraceHeaderOptions`); both are `omitempty`.
pub const HeaderOptions = struct {
    decoder_name: ?[]const u8 = null,
    peer_ids: ?[]const []const u8 = null,
};

/// Inputs for the header line (Go `traceHeader`). `t0` is a pre-formatted
/// RFC3339 string; `topology` and `config` are raw JSON inserted verbatim
/// (Go marshals `Topology` and treats `Config` as `json.RawMessage`).
pub const Header = struct {
    t0: []const u8,
    nodes: []const []const u8,
    topology: []const u8,
    config: []const u8,
    options: HeaderOptions = .{},
};

pub const TraceWriter = struct {
    allocator: Allocator,
    out: std.ArrayListUnmanaged(u8) = .empty,
    offset: usize = 0,
    index_interval_us: i64 = default_index_interval_us,
    last_index_ts: i64 = 0,
    index: std.ArrayListUnmanaged([2]i64) = .empty,

    /// Creates a writer and emits the header line (Go `NewTraceWriterWithOptions`).
    pub fn init(allocator: Allocator, header: Header) Allocator.Error!TraceWriter {
        var tw = TraceWriter{ .allocator = allocator };
        errdefer tw.deinit();

        var line: std.ArrayListUnmanaged(u8) = .empty;
        defer line.deinit(allocator);

        try line.appendSlice(allocator, "{\"v\":");
        try appendInt(&line, allocator, trace_version);
        try line.appendSlice(allocator, ",\"t0\":");
        try appendJsonString(&line, allocator, header.t0);
        try line.appendSlice(allocator, ",\"nodes\":");
        try appendJsonStringArray(&line, allocator, header.nodes);
        try line.appendSlice(allocator, ",\"topology\":");
        try line.appendSlice(allocator, header.topology);
        try line.appendSlice(allocator, ",\"config\":");
        // Go `json.RawMessage(nil)` marshals as `null`.
        try line.appendSlice(allocator, if (header.config.len == 0) "null" else header.config);
        if (header.options.decoder_name) |dn| {
            if (dn.len != 0) {
                try line.appendSlice(allocator, ",\"decoderName\":");
                try appendJsonString(&line, allocator, dn);
            }
        }
        if (header.options.peer_ids) |ids| {
            if (ids.len != 0) {
                try line.appendSlice(allocator, ",\"peer_ids\":");
                try appendJsonStringArray(&line, allocator, ids);
            }
        }
        try line.append(allocator, '}');
        try line.append(allocator, '\n');

        try tw.out.appendSlice(allocator, line.items);
        tw.offset = line.items.len;
        try tw.index.append(allocator, .{ 0, @intCast(line.items.len) });
        return tw;
    }

    pub fn deinit(self: *TraceWriter) void {
        self.out.deinit(self.allocator);
        self.index.deinit(self.allocator);
        self.* = undefined;
    }

    /// Writes one event tuple `[usec, node, ev, args...]` (Go `WriteEvent`).
    /// `usec` is the event time relative to `t0`, in microseconds.
    pub fn writeEvent(self: *TraceWriter, usec: i64, node: i64, ev: []const u8, args: []const Arg) Allocator.Error!void {
        const a = self.allocator;
        var line: std.ArrayListUnmanaged(u8) = .empty;
        defer line.deinit(a);

        try line.append(a, '[');
        try appendInt(&line, a, usec);
        try line.append(a, ',');
        try appendInt(&line, a, node);
        try line.append(a, ',');
        try appendJsonString(&line, a, ev);
        for (args) |arg| {
            try line.append(a, ',');
            switch (arg) {
                .int => |v| try appendInt(&line, a, v),
                .str => |s| try appendJsonString(&line, a, s),
            }
        }
        try line.append(a, ']');
        try line.append(a, '\n');

        // Index cadence + offset bookkeeping mirror Go `WriteEvent` exactly:
        // the recorded offset is the byte position where this line begins.
        if (usec - self.last_index_ts >= self.index_interval_us) {
            try self.index.append(a, .{ usec, @intCast(self.offset) });
            self.last_index_ts = usec;
        }
        try self.out.appendSlice(a, line.items);
        self.offset += line.items.len;
    }

    /// Writes the footer line and finishes the trace (Go `Close`).
    /// `duration_us` is the total run duration in microseconds; the Zig sim
    /// supplies it explicitly (Go computes `time.Since(t0)`).
    pub fn close(self: *TraceWriter, duration_us: i64) Allocator.Error!void {
        const a = self.allocator;
        var line: std.ArrayListUnmanaged(u8) = .empty;
        defer line.deinit(a);

        try line.appendSlice(a, "{\"end\":true,\"duration\":");
        try appendInt(&line, a, duration_us);
        try line.appendSlice(a, ",\"index\":[");
        for (self.index.items, 0..) |entry, i| {
            if (i != 0) try line.append(a, ',');
            try line.append(a, '[');
            try appendInt(&line, a, entry[0]);
            try line.append(a, ',');
            try appendInt(&line, a, entry[1]);
            try line.append(a, ']');
        }
        try line.appendSlice(a, "]}");
        try line.append(a, '\n');

        try self.out.appendSlice(a, line.items);
        self.offset += line.items.len;
    }

    /// The accumulated trace bytes (header + events + footer).
    pub fn bytes(self: *const TraceWriter) []const u8 {
        return self.out.items;
    }
};

fn appendInt(list: *std.ArrayListUnmanaged(u8), allocator: Allocator, value: i64) Allocator.Error!void {
    var buf: [24]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{d}", .{value}) catch unreachable;
    try list.appendSlice(allocator, s);
}

/// JSON string per Go `encoding/json`: quote, escape `"` `\` and C0 controls,
/// and HTML-escape `<` `>` `&` (Go's default `SetEscapeHTML(true)`).
fn appendJsonString(list: *std.ArrayListUnmanaged(u8), allocator: Allocator, s: []const u8) Allocator.Error!void {
    try list.append(allocator, '"');
    for (s) |c| {
        switch (c) {
            '"' => try list.appendSlice(allocator, "\\\""),
            '\\' => try list.appendSlice(allocator, "\\\\"),
            '\n' => try list.appendSlice(allocator, "\\n"),
            '\r' => try list.appendSlice(allocator, "\\r"),
            '\t' => try list.appendSlice(allocator, "\\t"),
            '<' => try list.appendSlice(allocator, "\\u003c"),
            '>' => try list.appendSlice(allocator, "\\u003e"),
            '&' => try list.appendSlice(allocator, "\\u0026"),
            else => {
                if (c < 0x20) {
                    const hex = "0123456789abcdef";
                    try list.appendSlice(allocator, "\\u00");
                    try list.append(allocator, hex[(c >> 4) & 0xf]);
                    try list.append(allocator, hex[c & 0xf]);
                } else {
                    try list.append(allocator, c);
                }
            },
        }
    }
    try list.append(allocator, '"');
}

fn appendJsonStringArray(list: *std.ArrayListUnmanaged(u8), allocator: Allocator, items: []const []const u8) Allocator.Error!void {
    try list.append(allocator, '[');
    for (items, 0..) |s, i| {
        if (i != 0) try list.append(allocator, ',');
        try appendJsonString(list, allocator, s);
    }
    try list.append(allocator, ']');
}

// ---------------------------------------------------------------------------
// Tests — golden bytes captured from the Go reference
// (`sim/trace_writer.go`, pin 741d8d9). Same inputs as Go's
// `TestTraceWriter_RoundTrip` in `sim/trace_writer_test.go`.
// ---------------------------------------------------------------------------

const testing = std.testing;

// Topology marshaled by Go for the round-trip fixture (verbatim in the header).
const golden_topology =
    "{\"nodes\":[{\"num\":0,\"upload_bw_mbps\":50,\"download_bw_mbps\":50}," ++
    "{\"num\":1,\"upload_bw_mbps\":50,\"download_bw_mbps\":50}," ++
    "{\"num\":2,\"upload_bw_mbps\":50,\"download_bw_mbps\":50}]," ++
    "\"edges\":[{\"source\":0,\"target\":1,\"latency_ms\":50}," ++
    "{\"source\":0,\"target\":2,\"latency_ms\":50}," ++
    "{\"source\":1,\"target\":2,\"latency_ms\":50}]}";

const golden_header =
    "{\"v\":1,\"t0\":\"2025-03-09T12:00:00Z\",\"nodes\":[\"n0\",\"n1\",\"n2\"]," ++
    "\"topology\":" ++ golden_topology ++ ",\"config\":{\"strategy\":\"rs\"}}\n";

fn buildRoundTrip(allocator: Allocator) !TraceWriter {
    var tw = try TraceWriter.init(allocator, .{
        .t0 = "2025-03-09T12:00:00Z",
        .nodes = &.{ "n0", "n1", "n2" },
        .topology = golden_topology,
        .config = "{\"strategy\":\"rs\"}",
    });
    errdefer tw.deinit();
    try tw.writeEvent(100, 0, event.session_started, &.{ .{ .str = "broadcast" }, .{ .str = "msg-0" }, .{ .int = 0 } });
    try tw.writeEvent(200, 0, event.chunk_sent, &.{ .{ .str = "1" }, .{ .str = "broadcast" }, .{ .str = "msg-0" }, .{ .int = 1420 } });
    try tw.writeEvent(500, 1, event.chunk_rcvd, &.{ .{ .str = "0" }, .{ .str = "broadcast" }, .{ .str = "msg-0" }, .{ .int = 0 } });
    try tw.writeEvent(1000, 1, event.strategy_progress, &.{ .{ .str = "broadcast" }, .{ .str = "msg-0" }, .{ .int = 4 }, .{ .int = 8 } });
    return tw;
}

test "header line matches Go NewTraceWriter golden bytes" {
    var tw = try TraceWriter.init(testing.allocator, .{
        .t0 = "2025-03-09T12:00:00Z",
        .nodes = &.{ "n0", "n1", "n2" },
        .topology = golden_topology,
        .config = "{\"strategy\":\"rs\"}",
    });
    defer tw.deinit();
    try testing.expectEqualStrings(golden_header, tw.bytes());
    // Header length feeds the index offset; Go reports 397.
    try testing.expectEqual(@as(usize, 397), golden_header.len);
    try testing.expectEqual(@as(usize, 397), tw.offset);
}

test "event rows match Go WriteEvent golden bytes" {
    var tw = try buildRoundTrip(testing.allocator);
    defer tw.deinit();

    const events_golden =
        "[100,0,\"ss\",\"broadcast\",\"msg-0\",0]\n" ++
        "[200,0,\"cs\",\"1\",\"broadcast\",\"msg-0\",1420]\n" ++
        "[500,1,\"cr\",\"0\",\"broadcast\",\"msg-0\",0]\n" ++
        "[1000,1,\"sp\",\"broadcast\",\"msg-0\",4,8]\n";
    try testing.expectEqualStrings(golden_header ++ events_golden, tw.bytes());
}

test "footer matches Go traceFooter golden bytes (short-run index)" {
    var tw = try buildRoundTrip(testing.allocator);
    defer tw.deinit();
    try tw.close(4242);

    // All four events land inside one 100 ms index window, so the index keeps
    // only the initial {0, headerLen} entry — matching the Go footer.
    try testing.expect(std.mem.endsWith(u8, tw.bytes(), "{\"end\":true,\"duration\":4242,\"index\":[[0,397]]}\n"));
}

test "index appends an entry once the 100 ms cadence is crossed" {
    var tw = try TraceWriter.init(testing.allocator, .{
        .t0 = "2025-03-09T12:00:00Z",
        .nodes = &.{"n0"},
        .topology = "{}",
        .config = "null",
    });
    defer tw.deinit();

    const header_len = tw.offset;
    try tw.writeEvent(50_000, 0, event.session_started, &.{}); // < 100 ms: no new index entry
    try testing.expectEqual(@as(usize, 1), tw.index.items.len);

    const off_before = tw.offset;
    try tw.writeEvent(100_000, 0, event.session_decoded, &.{}); // >= 100 ms: append {ts, offset}
    try testing.expectEqual(@as(usize, 2), tw.index.items.len);
    try testing.expectEqual(@as(i64, 100_000), tw.index.items[1][0]);
    try testing.expectEqual(@as(i64, @intCast(off_before)), tw.index.items[1][1]);
    try testing.expect(header_len > 0);
}

test "empty config marshals as null (Go json.RawMessage nil)" {
    var tw = try TraceWriter.init(testing.allocator, .{
        .t0 = "2025-01-01T00:00:00Z",
        .nodes = &.{},
        .topology = "{}",
        .config = "",
    });
    defer tw.deinit();
    try testing.expect(std.mem.indexOf(u8, tw.bytes(), "\"config\":null") != null);
}

test "header options add decoderName and peer_ids" {
    var tw = try TraceWriter.init(testing.allocator, .{
        .t0 = "2025-01-01T00:00:00Z",
        .nodes = &.{"n0"},
        .topology = "{}",
        .config = "null",
        .options = .{ .decoder_name = "rs", .peer_ids = &.{ "p0", "p1" } },
    });
    defer tw.deinit();
    try testing.expect(std.mem.indexOf(u8, tw.bytes(), "\"decoderName\":\"rs\"") != null);
    try testing.expect(std.mem.indexOf(u8, tw.bytes(), "\"peer_ids\":[\"p0\",\"p1\"]") != null);
}

test "json string escaping matches Go encoding/json defaults" {
    var tw = try TraceWriter.init(testing.allocator, .{
        .t0 = "t",
        .nodes = &.{},
        .topology = "{}",
        .config = "null",
    });
    defer tw.deinit();
    try tw.writeEvent(0, 0, "ce", &.{.{ .str = "a\"b\\c\n<&>" }});
    try testing.expect(std.mem.endsWith(u8, tw.bytes(), "[0,0,\"ce\",\"a\\\"b\\\\c\\n\\u003c\\u0026\\u003e\"]\n"));
}
