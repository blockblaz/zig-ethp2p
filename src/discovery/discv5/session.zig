//! discv5 per-peer session state.
//!
//! A session is established after a successful WHOAREYOU / Handshake exchange.
//! Once established, messages are encrypted with the derived AES-128-GCM keys
//! and the nonce counter is incremented for each packet.

const std = @import("std");
const crypto = @import("crypto.zig");

pub const SessionError = error{
    /// Nonce counter wrapped (2^96 packets — effectively unreachable).
    NonceOverflow,
    /// Decryption or authentication failed.
    AuthenticationFailed,
};

pub const SessionState = enum {
    /// No session; awaiting WHOAREYOU / Handshake.
    idle,
    /// WHOAREYOU sent; awaiting Handshake reply.
    awaiting_handshake,
    /// Session established; messages can be encrypted/decrypted.
    established,
};

pub const Session = struct {
    state: SessionState = .idle,
    keys: crypto.SessionKeys = undefined,
    /// 12-byte nonce: first 4 bytes are a packet counter (big-endian); last 8 are random.
    nonce_base: [8]u8 = [_]u8{0} ** 8,
    nonce_counter: u32 = 0,
    /// id-nonce used during handshake (retained for key derivation).
    id_nonce: [16]u8 = [_]u8{0} ** 16,
    /// ENR seq of the last-known record for this peer.
    peer_enr_seq: u64 = 0,

    pub fn init(nonce_base: [8]u8) Session {
        return .{ .nonce_base = nonce_base };
    }

    /// Transition to `awaiting_handshake`, recording the id-nonce we sent.
    pub fn beginHandshake(self: *Session, id_nonce: [16]u8) void {
        self.id_nonce = id_nonce;
        self.state = .awaiting_handshake;
    }

    /// Finalise session keys after a successful Handshake.
    pub fn establish(self: *Session, keys: crypto.SessionKeys) void {
        self.keys = keys;
        self.nonce_counter = 0;
        self.state = .established;
    }

    /// Build the next unique 12-byte nonce.
    pub fn nextNonce(self: *Session) SessionError![crypto.aes_nonce_len]u8 {
        const counter = self.nonce_counter;
        self.nonce_counter = std.math.add(u32, counter, 1) catch return error.NonceOverflow;
        var nonce: [crypto.aes_nonce_len]u8 = undefined;
        std.mem.writeInt(u32, nonce[0..4], counter, .big);
        @memcpy(nonce[4..], &self.nonce_base);
        return nonce;
    }

    pub fn isEstablished(self: *const Session) bool {
        return self.state == .established;
    }
};

// ---------------------------------------------------------------------------
// Session table — keyed by remote NodeId
// ---------------------------------------------------------------------------

pub const SessionTable = struct {
    map: std.AutoHashMapUnmanaged([32]u8, Session),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) SessionTable {
        return .{ .map = .{}, .allocator = allocator };
    }

    pub fn deinit(self: *SessionTable) void {
        self.map.deinit(self.allocator);
    }

    pub fn get(self: *SessionTable, node_id: [32]u8) ?*Session {
        return self.map.getPtr(node_id);
    }

    pub fn getOrCreate(self: *SessionTable, node_id: [32]u8, nonce_base: [8]u8) std.mem.Allocator.Error!*Session {
        const gop = try self.map.getOrPut(self.allocator, node_id);
        if (!gop.found_existing) gop.value_ptr.* = Session.init(nonce_base);
        return gop.value_ptr;
    }

    pub fn remove(self: *SessionTable, node_id: [32]u8) void {
        _ = self.map.remove(node_id);
    }

    pub fn count(self: *const SessionTable) usize {
        return self.map.count();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "session nonce increments" {
    var s = Session.init([_]u8{0xAB} ** 8);
    s.state = .established;
    const n0 = try s.nextNonce();
    const n1 = try s.nextNonce();
    try std.testing.expect(!std.mem.eql(u8, &n0, &n1));
    // Counter occupies first 4 bytes.
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, n0[0..4], .big));
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, n1[0..4], .big));
}

test "session table getOrCreate is idempotent" {
    const gpa = std.testing.allocator;
    var table = SessionTable.init(gpa);
    defer table.deinit();

    const id = [_]u8{1} ** 32;
    const s1 = try table.getOrCreate(id, [_]u8{0} ** 8);
    const s2 = try table.getOrCreate(id, [_]u8{0} ** 8);
    try std.testing.expectEqual(s1, s2);
    try std.testing.expectEqual(@as(usize, 1), table.count());
}
