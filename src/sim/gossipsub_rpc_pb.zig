//! Subset of [go-libp2p-pubsub `rpc.proto`](https://github.com/libp2p/go-libp2p-pubsub/blob/master/pb/rpc.proto):
//! `ControlIHave` / `ControlIWant`, full `ControlMessage` (graft / prune / idontwant), top-level
//! `RPC` (`subscriptions`, `publish`, `control`), and unsigned-varint length-prefix helpers for
//! stream framing. `RPC.partial` (field 10) is supported as an opaque length-delimited payload;
//! use `PartialMessagesExtension` helpers to build or parse that body. Other extension field
//! numbers are still skipped on decode.
//!
//! The ethp2p reference simulation uses `StrictNoSign` + `NoAuthor` (Prysm-aligned, `db6e941`),
//! so gossip `Message` objects on the wire carry only `data` and `topic`; `from`, `seqno`,
//! `signature`, and `key` are absent. `GossipMessageRef` defaults all of those to `null`, which
//! produces the correct (absent) encoding.

const std = @import("std");
const varint = @import("../wire/varint.zig");

const Allocator = std.mem.Allocator;

fn appendVarintUnmanaged(list: *std.ArrayListUnmanaged(u8), allocator: Allocator, value: u64) Allocator.Error!void {
    var v = value;
    while (v >= 0x80) {
        try list.append(allocator, @as(u8, @truncate(v & 0x7f | 0x80)));
        v >>= 7;
    }
    try list.append(allocator, @as(u8, @truncate(v)));
}

fn appendTagWire(list: *std.ArrayListUnmanaged(u8), allocator: Allocator, field_num: u32, wire_type: u32) Allocator.Error!void {
    const tag = (@as(u64, field_num) << 3) | @as(u64, wire_type);
    try appendVarintUnmanaged(list, allocator, tag);
}

fn appendTagVarintField(list: *std.ArrayListUnmanaged(u8), allocator: Allocator, field_num: u32, value: u64) Allocator.Error!void {
    try appendTagWire(list, allocator, field_num, 0);
    try appendVarintUnmanaged(list, allocator, value);
}

fn skipProtoField(buf: []const u8, offset: *usize, wire: u32) DecodeError!void {
    switch (wire) {
        0 => {
            _ = try varint.decode(buf, offset);
        },
        1 => {
            if (buf.len - offset.* < 8) return error.Truncated;
            offset.* += 8;
        },
        2 => {
            const plen = try varint.decode(buf, offset);
            if (buf.len - offset.* < plen) return error.Truncated;
            offset.* += @intCast(plen);
        },
        5 => {
            if (buf.len - offset.* < 4) return error.Truncated;
            offset.* += 4;
        },
        else => return error.BadWireType,
    }
}

fn decodeLengthDelimited(buf: []const u8, offset: *usize) DecodeError![]const u8 {
    const plen = try varint.decode(buf, offset);
    if (buf.len - offset.* < plen) return error.Truncated;
    const start = offset.*;
    offset.* += @intCast(plen);
    return buf[start..][0..@intCast(plen)];
}

pub const DecodeError = varint.DecodeError || error{ BadWireType, BadTag };

pub const IHave = struct {
    topic_id: ?[]const u8,
    message_ids: []const []const u8,
};

pub const IHaveOwned = struct {
    topic_id: ?[]u8,
    message_ids: [][]u8,

    pub fn deinit(self: *IHaveOwned, allocator: Allocator) void {
        if (self.topic_id) |t| allocator.free(t);
        for (self.message_ids) |m| allocator.free(m);
        allocator.free(self.message_ids);
        self.* = undefined;
    }
};

pub const IWantOwned = struct {
    message_ids: [][]u8,

    pub fn deinit(self: *IWantOwned, allocator: Allocator) void {
        for (self.message_ids) |m| allocator.free(m);
        allocator.free(self.message_ids);
        self.* = undefined;
    }
};

fn appendTagLenBytes(list: *std.ArrayListUnmanaged(u8), allocator: Allocator, field_num: u32, payload: []const u8) Allocator.Error!void {
    try appendTagWire(list, allocator, field_num, 2);
    try appendVarintUnmanaged(list, allocator, @as(u64, @intCast(payload.len)));
    try list.appendSlice(allocator, payload);
}

/// Serializes `ControlIHave` (message body only, not wrapped in `ControlMessage`).
pub fn encodeIHave(allocator: Allocator, topic: ?[]const u8, message_ids: []const []const u8) Allocator.Error![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .{};
    errdefer list.deinit(allocator);
    if (topic) |t| {
        try appendTagLenBytes(&list, allocator, 1, t);
    }
    for (message_ids) |mid| {
        try appendTagLenBytes(&list, allocator, 2, mid);
    }
    return try list.toOwnedSlice(allocator);
}

/// Serializes `ControlIWant` (message body only).
pub fn encodeIWant(allocator: Allocator, message_ids: []const []const u8) Allocator.Error![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .{};
    errdefer list.deinit(allocator);
    for (message_ids) |mid| {
        try appendTagLenBytes(&list, allocator, 1, mid);
    }
    return try list.toOwnedSlice(allocator);
}

/// Top-level `RPC` with only `control` set (field 3). `control_body` is a serialized `ControlMessage`.
pub fn encodeRpcEnvelopeControl(allocator: Allocator, control_body: []const u8) Allocator.Error![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .{};
    errdefer list.deinit(allocator);
    try appendTagLenBytes(&list, allocator, 3, control_body);
    return try list.toOwnedSlice(allocator);
}

/// Parses `RPC` that consists solely of one `control` (field 3) length-delimited payload.
pub fn decodeRpcControlOnly(buf: []const u8) DecodeError![]const u8 {
    var offset: usize = 0;
    const tl = try decodeTagLen(buf, &offset);
    if (tl.field != 3) return error.BadTag;
    if (offset != buf.len) return error.BadTag;
    return tl.payload;
}

/// Wraps one `encodeIHave` payload as `ControlMessage.ihave` (field 1, repeated).
pub fn encodeControlMessageSingleIHave(allocator: Allocator, ihave_body: []const u8) Allocator.Error![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .{};
    errdefer list.deinit(allocator);
    try appendTagLenBytes(&list, allocator, 1, ihave_body);
    return try list.toOwnedSlice(allocator);
}

fn decodeTagLen(buf: []const u8, offset: *usize) DecodeError!struct { field: u32, payload: []const u8 } {
    if (offset.* >= buf.len) return error.Truncated;
    const tag = try varint.decode(buf, offset);
    const field: u32 = @intCast(tag >> 3);
    const wire: u32 = @intCast(tag & 7);
    if (wire != 2) return error.BadWireType;
    const plen = try varint.decode(buf, offset);
    if (buf.len - offset.* < plen) return error.Truncated;
    const start = offset.*;
    offset.* += @intCast(plen);
    return .{ .field = field, .payload = buf[start..][0..@intCast(plen)] };
}

pub fn decodeIHaveOwned(allocator: Allocator, buf: []const u8) (DecodeError || Allocator.Error)!IHaveOwned {
    var offset: usize = 0;
    var topic: ?[]u8 = null;
    var ids: std.ArrayListUnmanaged([]u8) = .{};
    errdefer {
        if (topic) |t| allocator.free(t);
        for (ids.items) |m| allocator.free(m);
        ids.deinit(allocator);
    }

    while (offset < buf.len) {
        const tl = try decodeTagLen(buf, &offset);
        switch (tl.field) {
            1 => {
                if (topic != null) return error.BadTag;
                topic = try allocator.dupe(u8, tl.payload);
            },
            2 => try ids.append(allocator, try allocator.dupe(u8, tl.payload)),
            else => return error.BadTag,
        }
    }

    return .{
        .topic_id = topic,
        .message_ids = try ids.toOwnedSlice(allocator),
    };
}

pub fn decodeIWantOwned(allocator: Allocator, buf: []const u8) (DecodeError || Allocator.Error)!IWantOwned {
    var offset: usize = 0;
    var ids: std.ArrayListUnmanaged([]u8) = .{};
    errdefer {
        for (ids.items) |m| allocator.free(m);
        ids.deinit(allocator);
    }

    while (offset < buf.len) {
        const tl = try decodeTagLen(buf, &offset);
        if (tl.field != 1) return error.BadTag;
        try ids.append(allocator, try allocator.dupe(u8, tl.payload));
    }

    return .{ .message_ids = try ids.toOwnedSlice(allocator) };
}

// --- `RPC.subscriptions` / `RPC.publish`, full `ControlMessage`, length-prefixed RPC (issue #12) ---

pub const SubOptsRef = struct {
    subscribe: ?bool = null,
    topicid: ?[]const u8 = null,
    requests_partial: ?bool = null,
    supports_sending_partial: ?bool = null,
};

pub const SubOptsOwned = struct {
    subscribe: ?bool = null,
    topicid: ?[]u8 = null,
    requests_partial: ?bool = null,
    supports_sending_partial: ?bool = null,

    pub fn deinit(self: *SubOptsOwned, allocator: Allocator) void {
        if (self.topicid) |t| allocator.free(t);
        self.* = .{};
    }
};

pub fn encodeSubOpts(allocator: Allocator, s: SubOptsRef) Allocator.Error![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .{};
    errdefer list.deinit(allocator);
    if (s.subscribe) |b| try appendTagVarintField(&list, allocator, 1, if (b) 1 else 0);
    if (s.topicid) |t| try appendTagLenBytes(&list, allocator, 2, t);
    if (s.requests_partial) |b| try appendTagVarintField(&list, allocator, 3, if (b) 1 else 0);
    if (s.supports_sending_partial) |b| try appendTagVarintField(&list, allocator, 4, if (b) 1 else 0);
    return try list.toOwnedSlice(allocator);
}

pub fn decodeSubOptsOwned(allocator: Allocator, buf: []const u8) (DecodeError || Allocator.Error)!SubOptsOwned {
    var offset: usize = 0;
    var out: SubOptsOwned = .{};
    errdefer out.deinit(allocator);

    while (offset < buf.len) {
        const tag = try varint.decode(buf, &offset);
        const field: u32 = @intCast(tag >> 3);
        const wire: u32 = @intCast(tag & 7);
        switch (field) {
            1 => {
                if (wire != 0) return error.BadWireType;
                if (out.subscribe != null) return error.BadTag;
                const v = try varint.decode(buf, &offset);
                if (v > 1) return error.BadTag;
                out.subscribe = v != 0;
            },
            2 => {
                if (wire != 2) return error.BadWireType;
                if (out.topicid != null) return error.BadTag;
                const pl = try decodeLengthDelimited(buf, &offset);
                out.topicid = try allocator.dupe(u8, pl);
            },
            3 => {
                if (wire != 0) return error.BadWireType;
                if (out.requests_partial != null) return error.BadTag;
                const v = try varint.decode(buf, &offset);
                if (v > 1) return error.BadTag;
                out.requests_partial = v != 0;
            },
            4 => {
                if (wire != 0) return error.BadWireType;
                if (out.supports_sending_partial != null) return error.BadTag;
                const v = try varint.decode(buf, &offset);
                if (v > 1) return error.BadTag;
                out.supports_sending_partial = v != 0;
            },
            else => try skipProtoField(buf, &offset, wire),
        }
    }
    return out;
}

pub const GossipMessageRef = struct {
    from: ?[]const u8 = null,
    data: ?[]const u8 = null,
    seqno: ?[]const u8 = null,
    topic: ?[]const u8 = null,
    signature: ?[]const u8 = null,
    key: ?[]const u8 = null,
};

pub const GossipMessageOwned = struct {
    from: ?[]u8 = null,
    data: ?[]u8 = null,
    seqno: ?[]u8 = null,
    topic: ?[]u8 = null,
    signature: ?[]u8 = null,
    key: ?[]u8 = null,

    pub fn deinit(self: *GossipMessageOwned, allocator: Allocator) void {
        if (self.from) |x| allocator.free(x);
        if (self.data) |x| allocator.free(x);
        if (self.seqno) |x| allocator.free(x);
        if (self.topic) |x| allocator.free(x);
        if (self.signature) |x| allocator.free(x);
        if (self.key) |x| allocator.free(x);
        self.* = .{};
    }
};

pub fn encodeGossipMessage(allocator: Allocator, m: GossipMessageRef) Allocator.Error![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .{};
    errdefer list.deinit(allocator);
    if (m.from) |x| try appendTagLenBytes(&list, allocator, 1, x);
    if (m.data) |x| try appendTagLenBytes(&list, allocator, 2, x);
    if (m.seqno) |x| try appendTagLenBytes(&list, allocator, 3, x);
    if (m.topic) |x| try appendTagLenBytes(&list, allocator, 4, x);
    if (m.signature) |x| try appendTagLenBytes(&list, allocator, 5, x);
    if (m.key) |x| try appendTagLenBytes(&list, allocator, 6, x);
    return try list.toOwnedSlice(allocator);
}

pub fn decodeGossipMessageOwned(allocator: Allocator, buf: []const u8) (DecodeError || Allocator.Error)!GossipMessageOwned {
    var offset: usize = 0;
    var out: GossipMessageOwned = .{};
    errdefer out.deinit(allocator);

    while (offset < buf.len) {
        const tag = try varint.decode(buf, &offset);
        const field: u32 = @intCast(tag >> 3);
        const wire: u32 = @intCast(tag & 7);
        if (wire != 2) return error.BadWireType;
        const pl = try decodeLengthDelimited(buf, &offset);
        switch (field) {
            1 => {
                if (out.from != null) return error.BadTag;
                out.from = try allocator.dupe(u8, pl);
            },
            2 => {
                if (out.data != null) return error.BadTag;
                out.data = try allocator.dupe(u8, pl);
            },
            3 => {
                if (out.seqno != null) return error.BadTag;
                out.seqno = try allocator.dupe(u8, pl);
            },
            4 => {
                if (out.topic != null) return error.BadTag;
                out.topic = try allocator.dupe(u8, pl);
            },
            5 => {
                if (out.signature != null) return error.BadTag;
                out.signature = try allocator.dupe(u8, pl);
            },
            6 => {
                if (out.key != null) return error.BadTag;
                out.key = try allocator.dupe(u8, pl);
            },
            else => return error.BadTag,
        }
    }
    return out;
}

pub const PeerInfoRef = struct {
    peer_id: ?[]const u8 = null,
    signed_peer_record: ?[]const u8 = null,
};

pub const PeerInfoOwned = struct {
    peer_id: ?[]u8 = null,
    signed_peer_record: ?[]u8 = null,

    pub fn deinit(self: *PeerInfoOwned, allocator: Allocator) void {
        if (self.peer_id) |x| allocator.free(x);
        if (self.signed_peer_record) |x| allocator.free(x);
        self.* = .{};
    }
};

pub fn encodePeerInfo(allocator: Allocator, p: PeerInfoRef) Allocator.Error![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .{};
    errdefer list.deinit(allocator);
    if (p.peer_id) |x| try appendTagLenBytes(&list, allocator, 1, x);
    if (p.signed_peer_record) |x| try appendTagLenBytes(&list, allocator, 2, x);
    return try list.toOwnedSlice(allocator);
}

pub fn decodePeerInfoOwned(allocator: Allocator, buf: []const u8) (DecodeError || Allocator.Error)!PeerInfoOwned {
    var offset: usize = 0;
    var out: PeerInfoOwned = .{};
    errdefer out.deinit(allocator);

    while (offset < buf.len) {
        const tag = try varint.decode(buf, &offset);
        const field: u32 = @intCast(tag >> 3);
        const wire: u32 = @intCast(tag & 7);
        if (wire != 2) return error.BadWireType;
        const pl = try decodeLengthDelimited(buf, &offset);
        switch (field) {
            1 => {
                if (out.peer_id != null) return error.BadTag;
                out.peer_id = try allocator.dupe(u8, pl);
            },
            2 => {
                if (out.signed_peer_record != null) return error.BadTag;
                out.signed_peer_record = try allocator.dupe(u8, pl);
            },
            else => try skipProtoField(buf, &offset, wire),
        }
    }
    return out;
}

pub const ControlGraftRef = struct {
    topic: ?[]const u8 = null,
};

pub const ControlGraftOwned = struct {
    topic: ?[]u8 = null,

    pub fn deinit(self: *ControlGraftOwned, allocator: Allocator) void {
        if (self.topic) |t| allocator.free(t);
        self.* = .{};
    }
};

pub fn encodeControlGraft(allocator: Allocator, g: ControlGraftRef) Allocator.Error![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .{};
    errdefer list.deinit(allocator);
    if (g.topic) |t| try appendTagLenBytes(&list, allocator, 1, t);
    return try list.toOwnedSlice(allocator);
}

pub fn decodeControlGraftOwned(allocator: Allocator, buf: []const u8) (DecodeError || Allocator.Error)!ControlGraftOwned {
    var offset: usize = 0;
    var out: ControlGraftOwned = .{};
    errdefer out.deinit(allocator);

    while (offset < buf.len) {
        const tag = try varint.decode(buf, &offset);
        const field: u32 = @intCast(tag >> 3);
        const wire: u32 = @intCast(tag & 7);
        if (field != 1) {
            try skipProtoField(buf, &offset, wire);
            continue;
        }
        if (wire != 2) return error.BadWireType;
        if (out.topic != null) return error.BadTag;
        const pl = try decodeLengthDelimited(buf, &offset);
        out.topic = try allocator.dupe(u8, pl);
    }
    return out;
}

pub const ControlPruneRef = struct {
    topic: ?[]const u8 = null,
    peers: []const PeerInfoRef = &.{},
    backoff: ?u64 = null,
};

pub const ControlPruneOwned = struct {
    topic: ?[]u8 = null,
    peers: []PeerInfoOwned,
    backoff: ?u64 = null,

    pub fn deinit(self: *ControlPruneOwned, allocator: Allocator) void {
        if (self.topic) |t| allocator.free(t);
        for (self.peers) |*p| p.deinit(allocator);
        allocator.free(self.peers);
        self.* = undefined;
    }
};

pub fn encodeControlPrune(allocator: Allocator, p: ControlPruneRef) Allocator.Error![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .{};
    errdefer list.deinit(allocator);
    if (p.topic) |t| try appendTagLenBytes(&list, allocator, 1, t);
    for (p.peers) |peer| {
        const inner = try encodePeerInfo(allocator, peer);
        defer allocator.free(inner);
        try appendTagLenBytes(&list, allocator, 2, inner);
    }
    if (p.backoff) |b| try appendTagVarintField(&list, allocator, 3, b);
    return try list.toOwnedSlice(allocator);
}

pub fn decodeControlPruneOwned(allocator: Allocator, buf: []const u8) (DecodeError || Allocator.Error)!ControlPruneOwned {
    var offset: usize = 0;
    var topic: ?[]u8 = null;
    var peer_list: std.ArrayListUnmanaged(PeerInfoOwned) = .{};
    errdefer {
        if (topic) |t| allocator.free(t);
        for (peer_list.items) |*x| x.deinit(allocator);
        peer_list.deinit(allocator);
    }
    var backoff: ?u64 = null;

    while (offset < buf.len) {
        const tag = try varint.decode(buf, &offset);
        const field: u32 = @intCast(tag >> 3);
        const wire: u32 = @intCast(tag & 7);
        switch (field) {
            1 => {
                if (wire != 2) return error.BadWireType;
                if (topic != null) return error.BadTag;
                const pl = try decodeLengthDelimited(buf, &offset);
                topic = try allocator.dupe(u8, pl);
            },
            2 => {
                if (wire != 2) return error.BadWireType;
                const pl = try decodeLengthDelimited(buf, &offset);
                try peer_list.append(allocator, try decodePeerInfoOwned(allocator, pl));
            },
            3 => {
                if (wire != 0) return error.BadWireType;
                if (backoff != null) return error.BadTag;
                backoff = try varint.decode(buf, &offset);
            },
            else => try skipProtoField(buf, &offset, wire),
        }
    }

    return .{
        .topic = topic,
        .peers = try peer_list.toOwnedSlice(allocator),
        .backoff = backoff,
    };
}

/// `ControlIDontWant` matches `ControlIWant` on the wire (`repeated string messageIDs = 1`).
pub const encodeControlIDontWant = encodeIWant;
pub const decodeControlIDontWantOwned = decodeIWantOwned;

pub const ControlMessageEncodeRef = struct {
    ihave: []const []const u8 = &.{},
    iwant: []const []const u8 = &.{},
    graft: []const []const u8 = &.{},
    prune: []const []const u8 = &.{},
    idontwant: []const []const u8 = &.{},
};

pub fn encodeControlMessage(allocator: Allocator, m: ControlMessageEncodeRef) Allocator.Error![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .{};
    errdefer list.deinit(allocator);
    for (m.ihave) |b| try appendTagLenBytes(&list, allocator, 1, b);
    for (m.iwant) |b| try appendTagLenBytes(&list, allocator, 2, b);
    for (m.graft) |b| try appendTagLenBytes(&list, allocator, 3, b);
    for (m.prune) |b| try appendTagLenBytes(&list, allocator, 4, b);
    for (m.idontwant) |b| try appendTagLenBytes(&list, allocator, 5, b);
    return try list.toOwnedSlice(allocator);
}

pub const ControlMessageOwned = struct {
    ihave: [][]u8,
    iwant: [][]u8,
    graft: [][]u8,
    prune: [][]u8,
    idontwant: [][]u8,

    pub fn deinit(self: *ControlMessageOwned, allocator: Allocator) void {
        for (self.ihave) |x| allocator.free(x);
        allocator.free(self.ihave);
        for (self.iwant) |x| allocator.free(x);
        allocator.free(self.iwant);
        for (self.graft) |x| allocator.free(x);
        allocator.free(self.graft);
        for (self.prune) |x| allocator.free(x);
        allocator.free(self.prune);
        for (self.idontwant) |x| allocator.free(x);
        allocator.free(self.idontwant);
        self.* = undefined;
    }
};

pub fn decodeControlMessageOwned(allocator: Allocator, buf: []const u8) (DecodeError || Allocator.Error)!ControlMessageOwned {
    var ihave: std.ArrayListUnmanaged([]u8) = .{};
    errdefer {
        for (ihave.items) |x| allocator.free(x);
        ihave.deinit(allocator);
    }
    var iwant: std.ArrayListUnmanaged([]u8) = .{};
    errdefer {
        for (iwant.items) |x| allocator.free(x);
        iwant.deinit(allocator);
    }
    var graft: std.ArrayListUnmanaged([]u8) = .{};
    errdefer {
        for (graft.items) |x| allocator.free(x);
        graft.deinit(allocator);
    }
    var prune: std.ArrayListUnmanaged([]u8) = .{};
    errdefer {
        for (prune.items) |x| allocator.free(x);
        prune.deinit(allocator);
    }
    var idontwant: std.ArrayListUnmanaged([]u8) = .{};
    errdefer {
        for (idontwant.items) |x| allocator.free(x);
        idontwant.deinit(allocator);
    }

    var offset: usize = 0;
    while (offset < buf.len) {
        const tag = try varint.decode(buf, &offset);
        const field: u32 = @intCast(tag >> 3);
        const wire: u32 = @intCast(tag & 7);
        if (wire != 2) return error.BadWireType;
        const pl = try decodeLengthDelimited(buf, &offset);
        {
            const owned = try allocator.dupe(u8, pl);
            errdefer allocator.free(owned);
            switch (field) {
                1 => try ihave.append(allocator, owned),
                2 => try iwant.append(allocator, owned),
                3 => try graft.append(allocator, owned),
                4 => try prune.append(allocator, owned),
                5 => try idontwant.append(allocator, owned),
                else => return error.BadTag,
            }
        }
    }

    return .{
        .ihave = try ihave.toOwnedSlice(allocator),
        .iwant = try iwant.toOwnedSlice(allocator),
        .graft = try graft.toOwnedSlice(allocator),
        .prune = try prune.toOwnedSlice(allocator),
        .idontwant = try idontwant.toOwnedSlice(allocator),
    };
}

pub const PartialMessagesExtensionRef = struct {
    topic_id: ?[]const u8 = null,
    group_id: ?[]const u8 = null,
    partial_message: ?[]const u8 = null,
    parts_metadata: ?[]const u8 = null,
};

pub const PartialMessagesExtensionOwned = struct {
    topic_id: ?[]u8 = null,
    group_id: ?[]u8 = null,
    partial_message: ?[]u8 = null,
    parts_metadata: ?[]u8 = null,

    pub fn deinit(self: *PartialMessagesExtensionOwned, allocator: Allocator) void {
        if (self.topic_id) |x| allocator.free(x);
        if (self.group_id) |x| allocator.free(x);
        if (self.partial_message) |x| allocator.free(x);
        if (self.parts_metadata) |x| allocator.free(x);
        self.* = .{};
    }
};

pub fn encodePartialMessagesExtension(allocator: Allocator, p: PartialMessagesExtensionRef) Allocator.Error![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .{};
    errdefer list.deinit(allocator);
    if (p.topic_id) |x| try appendTagLenBytes(&list, allocator, 1, x);
    if (p.group_id) |x| try appendTagLenBytes(&list, allocator, 2, x);
    if (p.partial_message) |x| try appendTagLenBytes(&list, allocator, 3, x);
    if (p.parts_metadata) |x| try appendTagLenBytes(&list, allocator, 4, x);
    return try list.toOwnedSlice(allocator);
}

pub fn decodePartialMessagesExtensionOwned(allocator: Allocator, buf: []const u8) (DecodeError || Allocator.Error)!PartialMessagesExtensionOwned {
    var offset: usize = 0;
    var out: PartialMessagesExtensionOwned = .{};
    errdefer out.deinit(allocator);

    while (offset < buf.len) {
        const tag = try varint.decode(buf, &offset);
        const field: u32 = @intCast(tag >> 3);
        const wire: u32 = @intCast(tag & 7);
        if (wire != 2) return error.BadWireType;
        const pl = try decodeLengthDelimited(buf, &offset);
        switch (field) {
            1 => {
                if (out.topic_id != null) return error.BadTag;
                out.topic_id = try allocator.dupe(u8, pl);
            },
            2 => {
                if (out.group_id != null) return error.BadTag;
                out.group_id = try allocator.dupe(u8, pl);
            },
            3 => {
                if (out.partial_message != null) return error.BadTag;
                out.partial_message = try allocator.dupe(u8, pl);
            },
            4 => {
                if (out.parts_metadata != null) return error.BadTag;
                out.parts_metadata = try allocator.dupe(u8, pl);
            },
            else => return error.BadTag,
        }
    }
    return out;
}

pub const RpcEncodeRef = struct {
    subscriptions: []const SubOptsRef = &.{},
    publish: []const GossipMessageRef = &.{},
    control: ?[]const u8 = null,
    /// Serialized `PartialMessagesExtension` (or other payload accepted by peers) for `RPC.partial` (field 10).
    partial: ?[]const u8 = null,
};

pub const RpcOwned = struct {
    subscriptions: []SubOptsOwned,
    publish: []GossipMessageOwned,
    control: ?[]u8,
    partial: ?[]u8,

    pub fn deinit(self: *RpcOwned, allocator: Allocator) void {
        for (self.subscriptions) |*s| s.deinit(allocator);
        allocator.free(self.subscriptions);
        for (self.publish) |*m| m.deinit(allocator);
        allocator.free(self.publish);
        if (self.control) |c| allocator.free(c);
        if (self.partial) |c| allocator.free(c);
        self.* = undefined;
    }
};

pub fn encodeRpc(allocator: Allocator, r: RpcEncodeRef) Allocator.Error![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .{};
    errdefer list.deinit(allocator);
    for (r.subscriptions) |s| {
        const inner = try encodeSubOpts(allocator, s);
        defer allocator.free(inner);
        try appendTagLenBytes(&list, allocator, 1, inner);
    }
    for (r.publish) |m| {
        const inner = try encodeGossipMessage(allocator, m);
        defer allocator.free(inner);
        try appendTagLenBytes(&list, allocator, 2, inner);
    }
    if (r.control) |c| {
        try appendTagLenBytes(&list, allocator, 3, c);
    }
    if (r.partial) |p| {
        try appendTagLenBytes(&list, allocator, 10, p);
    }
    return try list.toOwnedSlice(allocator);
}

pub fn decodeRpcOwned(allocator: Allocator, buf: []const u8) (DecodeError || Allocator.Error)!RpcOwned {
    var offset: usize = 0;
    var subs: std.ArrayListUnmanaged(SubOptsOwned) = .{};
    errdefer {
        for (subs.items) |*s| s.deinit(allocator);
        subs.deinit(allocator);
    }
    var pubs: std.ArrayListUnmanaged(GossipMessageOwned) = .{};
    errdefer {
        for (pubs.items) |*m| m.deinit(allocator);
        pubs.deinit(allocator);
    }
    var control: ?[]u8 = null;
    errdefer if (control) |c| allocator.free(c);
    var partial: ?[]u8 = null;
    errdefer if (partial) |c| allocator.free(c);

    while (offset < buf.len) {
        const tag = try varint.decode(buf, &offset);
        const field: u32 = @intCast(tag >> 3);
        const wire: u32 = @intCast(tag & 7);
        switch (field) {
            1 => {
                if (wire != 2) return error.BadWireType;
                const pl = try decodeLengthDelimited(buf, &offset);
                try subs.append(allocator, try decodeSubOptsOwned(allocator, pl));
            },
            2 => {
                if (wire != 2) return error.BadWireType;
                const pl = try decodeLengthDelimited(buf, &offset);
                try pubs.append(allocator, try decodeGossipMessageOwned(allocator, pl));
            },
            3 => {
                if (wire != 2) return error.BadWireType;
                if (control != null) return error.BadTag;
                const pl = try decodeLengthDelimited(buf, &offset);
                control = try allocator.dupe(u8, pl);
            },
            10 => {
                if (wire != 2) return error.BadWireType;
                if (partial != null) return error.BadTag;
                const pl = try decodeLengthDelimited(buf, &offset);
                partial = try allocator.dupe(u8, pl);
            },
            else => try skipProtoField(buf, &offset, wire),
        }
    }

    return .{
        .subscriptions = try subs.toOwnedSlice(allocator),
        .publish = try pubs.toOwnedSlice(allocator),
        .control = control,
        .partial = partial,
    };
}

/// Prefixes `rpc_body` with an unsigned protobuf varint of its length (common libp2p stream framing).
pub fn encodeRpcLengthPrefixed(allocator: Allocator, rpc_body: []const u8) Allocator.Error![]u8 {
    var list: std.ArrayListUnmanaged(u8) = .{};
    errdefer list.deinit(allocator);
    try appendVarintUnmanaged(&list, allocator, @intCast(rpc_body.len));
    try list.appendSlice(allocator, rpc_body);
    return try list.toOwnedSlice(allocator);
}

pub fn decodeRpcLengthPrefixedPrefix(buf: []const u8) DecodeError!struct { rpc: []const u8, rest: []const u8 } {
    var off: usize = 0;
    const len_u = try varint.decode(buf, &off);
    if (len_u > std.math.maxInt(usize)) return error.Truncated;
    const len: usize = @intCast(len_u);
    if (buf.len - off < len) return error.Truncated;
    return .{ .rpc = buf[off..][0..len], .rest = buf[off + len ..] };
}

test "IHave roundtrip" {
    const gpa = std.testing.allocator;
    const enc = try encodeIHave(gpa, "broadcast-test", &.{ "a", "bb" });
    defer gpa.free(enc);

    var dec = try decodeIHaveOwned(gpa, enc);
    defer dec.deinit(gpa);

    try std.testing.expect(dec.topic_id != null);
    try std.testing.expectEqualStrings("broadcast-test", dec.topic_id.?);
    try std.testing.expectEqual(@as(usize, 2), dec.message_ids.len);
    try std.testing.expectEqualStrings("a", dec.message_ids[0]);
    try std.testing.expectEqualStrings("bb", dec.message_ids[1]);
}

test "full RPC subscriptions publish control roundtrip" {
    const gpa = std.testing.allocator;
    const ih = try encodeIHave(gpa, "top", &.{"mid"});
    defer gpa.free(ih);
    const ctl = try encodeControlMessage(gpa, .{ .ihave = &.{ih} });
    defer gpa.free(ctl);

    const rpc_enc = try encodeRpc(gpa, .{
        .subscriptions = &.{
            .{ .subscribe = true, .topicid = "mesh/1" },
        },
        .publish = &.{
            .{ .topic = "mesh/1", .data = "hello" },
        },
        .control = ctl,
    });
    defer gpa.free(rpc_enc);

    var dec = try decodeRpcOwned(gpa, rpc_enc);
    defer dec.deinit(gpa);
    try std.testing.expect(dec.partial == null);

    try std.testing.expectEqual(@as(usize, 1), dec.subscriptions.len);
    try std.testing.expect(dec.subscriptions[0].subscribe.?);
    try std.testing.expectEqualStrings("mesh/1", dec.subscriptions[0].topicid.?);
    try std.testing.expectEqual(@as(usize, 1), dec.publish.len);
    try std.testing.expectEqualStrings("mesh/1", dec.publish[0].topic.?);
    try std.testing.expectEqualStrings("hello", dec.publish[0].data.?);
    try std.testing.expect(dec.control != null);

    var ctl_dec = try decodeControlMessageOwned(gpa, dec.control.?);
    defer ctl_dec.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 1), ctl_dec.ihave.len);
    var ih_dec = try decodeIHaveOwned(gpa, ctl_dec.ihave[0]);
    defer ih_dec.deinit(gpa);
    try std.testing.expectEqualStrings("top", ih_dec.topic_id.?);
    try std.testing.expectEqualStrings("mid", ih_dec.message_ids[0]);
}

test "PartialMessagesExtension and RPC.partial field 10 roundtrip" {
    const gpa = std.testing.allocator;
    const pext = try encodePartialMessagesExtension(gpa, .{
        .topic_id = "topic-p",
        .group_id = "grp",
        .partial_message = "blob",
    });
    defer gpa.free(pext);

    var pdec = try decodePartialMessagesExtensionOwned(gpa, pext);
    defer pdec.deinit(gpa);
    try std.testing.expectEqualStrings("topic-p", pdec.topic_id.?);
    try std.testing.expectEqualStrings("grp", pdec.group_id.?);
    try std.testing.expectEqualStrings("blob", pdec.partial_message.?);

    const rpc_enc = try encodeRpc(gpa, .{
        .subscriptions = &.{.{ .subscribe = true, .topicid = "t" }},
        .partial = pext,
    });
    defer gpa.free(rpc_enc);

    var rdec = try decodeRpcOwned(gpa, rpc_enc);
    defer rdec.deinit(gpa);
    try std.testing.expect(rdec.partial != null);
    var pdec2 = try decodePartialMessagesExtensionOwned(gpa, rdec.partial.?);
    defer pdec2.deinit(gpa);
    try std.testing.expectEqualStrings("topic-p", pdec2.topic_id.?);
}

test "ControlMessage graft prune idontwant roundtrip" {
    const gpa = std.testing.allocator;
    const gr = try encodeControlGraft(gpa, .{ .topic = "t" });
    defer gpa.free(gr);
    const pr = try encodeControlPrune(gpa, .{
        .topic = "p",
        .peers = &.{.{ .peer_id = "peerA" }},
        .backoff = 60,
    });
    defer gpa.free(pr);
    const idw = try encodeControlIDontWant(gpa, &.{ "a", "b" });
    defer gpa.free(idw);

    const ctl = try encodeControlMessage(gpa, .{
        .graft = &.{gr},
        .prune = &.{pr},
        .idontwant = &.{idw},
    });
    defer gpa.free(ctl);

    var dec = try decodeControlMessageOwned(gpa, ctl);
    defer dec.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 1), dec.graft.len);
    try std.testing.expectEqual(@as(usize, 1), dec.prune.len);
    try std.testing.expectEqual(@as(usize, 1), dec.idontwant.len);

    var gdec = try decodeControlGraftOwned(gpa, dec.graft[0]);
    defer gdec.deinit(gpa);
    try std.testing.expectEqualStrings("t", gdec.topic.?);

    var pdec = try decodeControlPruneOwned(gpa, dec.prune[0]);
    defer pdec.deinit(gpa);
    try std.testing.expectEqualStrings("p", pdec.topic.?);
    try std.testing.expectEqual(@as(usize, 1), pdec.peers.len);
    try std.testing.expectEqualStrings("peerA", pdec.peers[0].peer_id.?);
    try std.testing.expectEqual(@as(u64, 60), pdec.backoff.?);

    var idwdec = try decodeControlIDontWantOwned(gpa, dec.idontwant[0]);
    defer idwdec.deinit(gpa);
    try std.testing.expectEqualStrings("a", idwdec.message_ids[0]);
    try std.testing.expectEqualStrings("b", idwdec.message_ids[1]);
}

test "RPC length-prefixed roundtrip" {
    const gpa = std.testing.allocator;
    const inner = try encodeRpc(gpa, .{ .publish = &.{.{ .data = "x" }} });
    defer gpa.free(inner);
    const framed = try encodeRpcLengthPrefixed(gpa, inner);
    defer gpa.free(framed);

    const pr = try decodeRpcLengthPrefixedPrefix(framed);
    try std.testing.expectEqualSlices(u8, inner, pr.rpc);
    try std.testing.expectEqual(@as(usize, 0), pr.rest.len);
}

test "IWant roundtrip" {
    const gpa = std.testing.allocator;
    const enc = try encodeIWant(gpa, &.{ "x", "yz" });
    defer gpa.free(enc);

    var dec = try decodeIWantOwned(gpa, enc);
    defer dec.deinit(gpa);

    try std.testing.expectEqual(@as(usize, 2), dec.message_ids.len);
    try std.testing.expectEqualStrings("x", dec.message_ids[0]);
    try std.testing.expectEqualStrings("yz", dec.message_ids[1]);
}

test "ControlMessage single IHave wrapper roundtrip" {
    const gpa = std.testing.allocator;
    const inner = try encodeIHave(gpa, "t", &.{"mid"});
    defer gpa.free(inner);
    const outer = try encodeControlMessageSingleIHave(gpa, inner);
    defer gpa.free(outer);

    var off: usize = 0;
    const tl = try decodeTagLen(outer, &off);
    try std.testing.expectEqual(@as(u32, 1), tl.field);
    try std.testing.expect(off == outer.len);

    var dec = try decodeIHaveOwned(gpa, tl.payload);
    defer dec.deinit(gpa);
    try std.testing.expectEqualStrings("t", dec.topic_id.?);
    try std.testing.expectEqualStrings("mid", dec.message_ids[0]);
}

test "RPC envelope control-only roundtrip" {
    const gpa = std.testing.allocator;
    const inner = try encodeIHave(gpa, "topic", &.{"m1"});
    defer gpa.free(inner);
    const ctl = try encodeControlMessageSingleIHave(gpa, inner);
    defer gpa.free(ctl);
    const rpc = try encodeRpcEnvelopeControl(gpa, ctl);
    defer gpa.free(rpc);

    const ctl2 = try decodeRpcControlOnly(rpc);
    try std.testing.expectEqualSlices(u8, ctl, ctl2);

    var off: usize = 0;
    const tl = try decodeTagLen(ctl2, &off);
    try std.testing.expectEqual(@as(u32, 1), tl.field);
    var dec = try decodeIHaveOwned(gpa, tl.payload);
    defer dec.deinit(gpa);
    try std.testing.expectEqualStrings("topic", dec.topic_id.?);
    try std.testing.expectEqualStrings("m1", dec.message_ids[0]);
}
