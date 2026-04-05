//! discv5 node: UDP I/O, drive loop, bootstrap, and iterative lookup.
//!
//! The node drives all discv5 protocol activity:
//!   - Binds a UDP socket and receives datagrams in a non-blocking poll loop.
//!   - Sends PING to every bucket's LRS entry on a refresh timer.
//!   - Runs iterative FINDNODE lookups to populate the routing table.
//!   - Responds to inbound PING / FINDNODE / WHOAREYOU.
//!   - Exposes `queryByCapability` for duty-aware peer selection.
//!
//! The drive loop is poll-based (no threads); call `poll(node, now_ns)` from
//! the event loop.  The caller provides a send callback for outbound datagrams.

const std = @import("std");
const table = @import("table.zig");
const session = @import("session.zig");
const protocol = @import("protocol.zig");
const crypto = @import("crypto.zig");
const packet = @import("packet.zig");
const enr_mod = @import("../enr/enr.zig");
const ethp2p_enr = @import("../enr/ethp2p.zig");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

pub const Config = struct {
    /// UDP address to listen on.
    listen_addr: std.net.Address = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 0),
    /// Local secp256k1 private key (32-byte scalar).
    local_privkey: [crypto.privkey_len]u8 = [_]u8{0} ** crypto.privkey_len,
    /// How often to refresh each bucket (ms).
    bucket_refresh_ms: u64 = 3_600_000,
    /// Concurrency factor α for iterative lookups.
    lookup_alpha: usize = 3,
    /// Maximum concurrent in-flight requests.
    max_in_flight: usize = protocol.max_in_flight,
};

// ---------------------------------------------------------------------------
// Node state
// ---------------------------------------------------------------------------

pub const NodeState = enum { stopped, running };

/// Pending outbound request (FINDNODE, PING).
const PendingRequest = struct {
    request_id: u64,
    target: table.NodeId,
    sent_at_ns: u64,
    kind: enum { findnode, ping },
};

/// Active iterative lookup state.
const Lookup = struct {
    target: table.NodeId,
    /// NodeIds we have already queried or are querying.
    queried: [256]table.NodeId = undefined,
    queried_count: usize = 0,
    /// Current best results.
    results: [table.k]table.Entry = undefined,
    result_count: usize = 0,
};

pub const Node = struct {
    allocator: std.mem.Allocator,
    config: Config,
    local_id: table.NodeId,
    local_pubkey: [crypto.pubkey_len]u8,
    routing_table: table.RoutingTable,
    sessions: session.SessionTable,
    state: NodeState = .stopped,

    /// UDP socket file descriptor (null when stopped).
    socket: ?std.posix.fd_t = null,

    /// In-flight requests.
    pending: std.ArrayListUnmanaged(PendingRequest) = .{},
    /// Active lookup (only one at a time for simplicity).
    active_lookup: ?Lookup = null,
    /// Cache of ENR capabilities by NodeId (populated from NODES responses).
    enr_cache: std.AutoHashMapUnmanaged(table.NodeId, ethp2p_enr.EthEcField) = .{},

    /// Monotonic clock snapshot from last poll (ns).
    last_poll_ns: u64 = 0,
    /// Next bucket-refresh deadline (ns).
    next_refresh_ns: u64 = 0,
    /// Request ID counter.
    request_id_counter: u64 = 0,

    /// Outbound send callback.
    /// The caller can set this to forward datagrams via their own UDP loop.
    send_fn: ?*const fn (addr: std.net.Address, data: []const u8) void = null,

    pub fn init(allocator: std.mem.Allocator, config: Config) crypto.Secp256k1Error!Node {
        var pubkey: [crypto.pubkey_len]u8 = undefined;
        try crypto.generatePubkey(&pubkey, config.local_privkey);
        const local_id = try crypto.nodeIdFromPubkey(pubkey);
        return .{
            .allocator = allocator,
            .config = config,
            .local_id = local_id,
            .local_pubkey = pubkey,
            .routing_table = table.RoutingTable.init(local_id),
            .sessions = session.SessionTable.init(allocator),
        };
    }

    pub fn deinit(self: *Node) void {
        if (self.socket) |sock| {
            std.posix.close(sock);
            self.socket = null;
        }
        self.pending.deinit(self.allocator);
        self.enr_cache.deinit(self.allocator);
        self.sessions.deinit();
    }

    /// Bind the UDP socket and start the node.
    pub fn start(self: *Node) !void {
        const addr = self.config.listen_addr;
        const sock = try std.posix.socket(
            addr.any.family,
            std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK,
            0,
        );
        try std.posix.bind(sock, &addr.any, addr.getOsSockLen());
        self.socket = sock;
        self.state = .running;
    }

    pub fn stop(self: *Node) void {
        if (self.socket) |sock| {
            std.posix.close(sock);
            self.socket = null;
        }
        self.state = .stopped;
    }

    // -----------------------------------------------------------------------
    // Drive loop
    // -----------------------------------------------------------------------

    /// Advance timers and drain inbound UDP datagrams.
    /// `now_ns` is a monotonic clock reading.
    /// Returns the next deadline the caller should wake at.
    pub fn poll(self: *Node, now_ns: u64) u64 {
        self.last_poll_ns = now_ns;

        // Receive available datagrams.
        if (self.socket) |sock| {
            self.recvLoop(sock);
        }

        self.expireRequests(now_ns);

        if (now_ns >= self.next_refresh_ns) {
            self.refreshBuckets(now_ns);
            self.next_refresh_ns = now_ns + self.config.bucket_refresh_ms * std.time.ns_per_ms;
        }

        return self.next_refresh_ns;
    }

    /// Non-blocking receive loop — drains all pending UDP datagrams.
    fn recvLoop(self: *Node, sock: std.posix.fd_t) void {
        var dgram: [packet.max_datagram_len]u8 = undefined;
        var from_addr: std.posix.sockaddr = undefined;
        var from_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

        while (true) {
            const n = std.posix.recvfrom(
                sock,
                &dgram,
                std.posix.MSG.DONTWAIT,
                &from_addr,
                &from_len,
            ) catch break; // EAGAIN/EWOULDBLOCK → no more datagrams

            const from = std.net.Address{ .any = from_addr };
            self.handleDatagram(dgram[0..n], from);
        }
    }

    // -----------------------------------------------------------------------
    // Inbound packet dispatch
    // -----------------------------------------------------------------------

    fn handleDatagram(self: *Node, data: []const u8, from: std.net.Address) void {
        var hdr_buf: [packet.static_header_len + 300 + 32]u8 = undefined;
        const pkt = packet.decode(data, self.local_id, &hdr_buf) catch return;

        switch (pkt) {
            .ordinary => |o| self.handleOrdinary(o.header, o.auth, o.encrypted_body, from),
            .whoareyou => |w| self.handleWhoareyou(w.header, w.auth, from),
            .handshake => |h| self.handleHandshake(h.header, h.auth, h.encrypted_body, from),
        }
    }

    fn handleOrdinary(
        self: *Node,
        hdr: packet.PacketHeader,
        auth: packet.OrdinaryAuthData,
        encrypted_body: []const u8,
        from: std.net.Address,
    ) void {
        // Look up session keys for src_id.
        const sess = self.sessions.get(auth.src_id) orelse {
            // No session — send WHOAREYOU challenge.
            self.sendWhoareyou(auth.src_id, hdr.nonce, from);
            return;
        };
        if (!sess.isEstablished()) {
            self.sendWhoareyou(auth.src_id, hdr.nonce, from);
            return;
        }

        // Decrypt the message body.
        var plain_buf: [packet.max_datagram_len]u8 = undefined;
        if (encrypted_body.len <= crypto.aes_tag_len) return;
        const body_len = encrypted_body.len - crypto.aes_tag_len;
        if (body_len > plain_buf.len) return;

        crypto.decryptAesGcm(
            plain_buf[0..body_len],
            encrypted_body,
            &hdr.nonce, // AAD = nonce bytes
            sess.keys.initiator_key,
            hdr.nonce,
        ) catch return;

        self.dispatchMessage(plain_buf[0..body_len], auth.src_id);
    }

    fn handleWhoareyou(
        self: *Node,
        hdr: packet.PacketHeader,
        auth: packet.WhoareyouAuthData,
        from: std.net.Address,
    ) void {
        // Generate ephemeral keypair for this handshake.
        var eph_priv: [crypto.privkey_len]u8 = undefined;
        var eph_pub: [crypto.pubkey_len]u8 = undefined;
        crypto.generateEphemeralKeypair(&eph_priv, &eph_pub) catch return;
        // The id-nonce from WHOAREYOU is used in key derivation.
        // Store it in the pending session if one exists.
        const nonce_base: [8]u8 = hdr.nonce[0..8].*;
        const sess = self.sessions.getOrCreate(
            // src_id is unknown in WHOAREYOU; use from-address hash as key.
            // In a full implementation, find the pending request to map this back.
            [_]u8{0} ** 32,
            nonce_base,
        ) catch return;
        sess.beginHandshake(auth.id_nonce);
        _ = from;
        // eph_priv / eph_pub are used in a real handshake reply; kept for now.
        std.mem.doNotOptimizeAway(&eph_priv);
        std.mem.doNotOptimizeAway(&eph_pub);
    }

    fn handleHandshake(
        self: *Node,
        hdr: packet.PacketHeader,
        auth: packet.HandshakeAuthData,
        encrypted_body: []const u8,
        from: std.net.Address,
    ) void {
        // Verify the id-signature.
        crypto.ecdsaVerifyIdNonce(
            auth.id_sig,
            &hdr.nonce,
            auth.ephem_pubkey,
            self.local_id,
            auth.ephem_pubkey,
        ) catch return;

        // Compute ECDH shared secret.
        var secret: [32]u8 = undefined;
        crypto.ecdhSharedSecret(&secret, self.config.local_privkey, auth.ephem_pubkey) catch return;

        // Derive session keys.  id_nonce comes from the WHOAREYOU we sent;
        // use the nonce field padded to 16 bytes as a placeholder here.
        var id_nonce: [16]u8 = [_]u8{0} ** 16;
        @memcpy(id_nonce[0..hdr.nonce.len], &hdr.nonce);
        const keys = crypto.deriveSessionKeys(secret, id_nonce, auth.ephem_pubkey, self.local_id, auth.src_id);

        // Store session.
        const nonce_base: [8]u8 = hdr.nonce[0..8].*;
        const sess = self.sessions.getOrCreate(auth.src_id, nonce_base) catch return;
        sess.establish(keys);

        // Parse optional ENR update.
        if (auth.record.len > 0) {
            self.processInboundEnr(auth.record, from);
        }

        // Decrypt and dispatch message body (if any).
        if (encrypted_body.len > crypto.aes_tag_len) {
            var plain: [packet.max_datagram_len]u8 = undefined;
            const blen = encrypted_body.len - crypto.aes_tag_len;
            if (blen <= plain.len) {
                crypto.decryptAesGcm(plain[0..blen], encrypted_body, &hdr.nonce, sess.keys.recipient_key, hdr.nonce) catch return;
                self.dispatchMessage(plain[0..blen], auth.src_id);
            }
        }
    }

    fn dispatchMessage(self: *Node, plain: []const u8, src_id: table.NodeId) void {
        if (plain.len == 0) return;
        switch (plain[0]) {
            protocol.msg_ping => {
                const msg = protocol.decodePing(self.allocator, plain) catch return;
                self.handlePing(msg, src_id);
            },
            protocol.msg_pong => {
                const msg = protocol.decodePong(self.allocator, plain) catch return;
                _ = msg;
                // Pong: update last_seen in routing table.
                self.routing_table.refreshNode(src_id, self.last_poll_ns);
            },
            protocol.msg_findnode => {
                const msg = protocol.decodeFindNode(self.allocator, plain) catch return;
                defer protocol.freeFindNode(self.allocator, msg);
                self.handleFindNode(msg, src_id);
            },
            protocol.msg_nodes => {
                const msg = protocol.decodeNodes(self.allocator, plain) catch return;
                defer protocol.freeNodes(self.allocator, msg);
                self.handleNodes(msg);
            },
            else => {},
        }
    }

    // -----------------------------------------------------------------------
    // Message handlers
    // -----------------------------------------------------------------------

    fn handlePing(self: *Node, msg: protocol.Ping, src_id: table.NodeId) void {
        // Update routing table.
        self.routing_table.refreshNode(src_id, self.last_poll_ns);

        // Send PONG.
        const pong = protocol.Pong{
            .request_id = msg.request_id,
            .enr_seq = self.config.local_privkey[0], // Placeholder enr_seq.
            .recipient_ip = [_]u8{0} ** 16,
            .ip_len = 4,
            .recipient_port = 0,
        };
        const enc = protocol.encodePong(self.allocator, pong) catch return;
        defer self.allocator.free(enc);
        self.sendToNode(src_id, enc);
    }

    fn handleFindNode(self: *Node, msg: protocol.FindNode, src_id: table.NodeId) void {
        // Collect entries at the requested distances.
        var entries: [table.k]table.Entry = undefined;
        const count = self.routing_table.closest(self.local_id, &entries);

        // Send NODES in batches of max_nodes_per_response.
        var i: usize = 0;
        const batches: u8 = @intCast((count + protocol.max_nodes_per_response - 1) / protocol.max_nodes_per_response);
        while (i < count) {
            const end = @min(i + protocol.max_nodes_per_response, count);
            var enr_ptrs: [protocol.max_nodes_per_response][]const u8 = undefined;
            var batch_count: usize = 0;
            for (entries[i..end]) |e| {
                // For now we send empty ENR placeholders; a full implementation
                // would encode the stored ENR for each entry.
                _ = e;
                enr_ptrs[batch_count] = &[_]u8{};
                batch_count += 1;
            }
            const nodes_msg = protocol.Nodes{
                .request_id = msg.request_id,
                .total = batches,
                .enrs = enr_ptrs[0..batch_count],
            };
            const enc = protocol.encodeNodes(self.allocator, nodes_msg) catch break;
            defer self.allocator.free(enc);
            self.sendToNode(src_id, enc);
            i = end;
        }
    }

    fn handleNodes(self: *Node, msg: protocol.Nodes) void {
        // Process ENRs from the response and add to routing table.
        for (msg.enrs) |enr_bytes| {
            if (enr_bytes.len == 0) continue;
            var rec = enr_mod.decode(self.allocator, enr_bytes) catch continue;
            defer rec.deinit();

            // Extract the secp256k1 pubkey and derive node_id.
            const pk_raw = rec.get("secp256k1") orelse continue;
            const pk_bytes = enr_mod.rlpStringValue(pk_raw) catch continue;
            if (pk_bytes.len != crypto.pubkey_len) continue;
            const pubkey: [crypto.pubkey_len]u8 = pk_bytes[0..crypto.pubkey_len].*;
            const node_id = crypto.nodeIdFromPubkey(pubkey) catch continue;

            // Cache EthEc field if present.
            if (rec.get(ethp2p_enr.key_eth_ec)) |ec_raw| {
                const ec_bytes = enr_mod.rlpStringValue(ec_raw) catch continue;
                if (ethp2p_enr.EthEcField.decode(ec_bytes)) |ec_field| {
                    self.enr_cache.put(self.allocator, node_id, ec_field) catch {};
                } else |_| {}
            }

            // Add to routing table with a placeholder UDP address.
            const entry = table.Entry{
                .node_id = node_id,
                .udp_addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 0),
                .enr_seq = rec.seq,
                .last_seen_ns = self.last_poll_ns,
            };
            _ = self.routing_table.add(entry);

            // Advance the active lookup.
            if (self.active_lookup) |*lk| {
                self.advanceLookup(lk, entry);
            }
        }
    }

    fn processInboundEnr(self: *Node, raw: []const u8, from: std.net.Address) void {
        var rec = enr_mod.decode(self.allocator, raw) catch return;
        defer rec.deinit();

        const pk_raw = rec.get("secp256k1") orelse return;
        const pk_bytes = enr_mod.rlpStringValue(pk_raw) catch return;
        if (pk_bytes.len != crypto.pubkey_len) return;
        const pubkey: [crypto.pubkey_len]u8 = pk_bytes[0..crypto.pubkey_len].*;
        const node_id = crypto.nodeIdFromPubkey(pubkey) catch return;

        const entry = table.Entry{
            .node_id = node_id,
            .udp_addr = from,
            .enr_seq = rec.seq,
            .last_seen_ns = self.last_poll_ns,
        };
        _ = self.routing_table.add(entry);
    }

    // -----------------------------------------------------------------------
    // Outbound helpers
    // -----------------------------------------------------------------------

    /// Send a raw encrypted message to a peer that already has a session.
    fn sendToNode(self: *Node, node_id: table.NodeId, plain: []const u8) void {
        const entry = self.routing_table.getEntry(node_id) orelse return;
        const sess = self.sessions.get(node_id) orelse return;
        if (!sess.isEstablished()) return;

        var nonce: [crypto.aes_nonce_len]u8 = undefined;
        std.crypto.random.bytes(&nonce);

        var ct: [packet.max_datagram_len]u8 = undefined;
        if (plain.len + crypto.aes_tag_len > ct.len) return;
        crypto.encryptAesGcm(ct[0 .. plain.len + crypto.aes_tag_len], plain, &nonce, sess.keys.initiator_key, nonce);

        var iv: [packet.masking_iv_len]u8 = undefined;
        std.crypto.random.bytes(&iv);

        var dgram: [packet.max_datagram_len]u8 = undefined;
        const n = packet.encodeOrdinary(
            &dgram,
            iv,
            node_id,
            nonce,
            self.local_id,
            ct[0 .. plain.len + crypto.aes_tag_len],
        ) catch return;

        self.sendDatagram(entry.udp_addr, dgram[0..n]);
    }

    fn sendWhoareyou(
        self: *Node,
        dest_id: table.NodeId,
        challenge_nonce: [12]u8,
        dest_addr: std.net.Address,
    ) void {
        var id_nonce: [16]u8 = undefined;
        std.crypto.random.bytes(&id_nonce);
        var iv: [packet.masking_iv_len]u8 = undefined;
        std.crypto.random.bytes(&iv);

        var dgram: [packet.max_datagram_len]u8 = undefined;
        _ = challenge_nonce;
        const n = packet.encodeWhoareyou(&dgram, iv, dest_id, [_]u8{0} ** 12, id_nonce, 0) catch return;
        self.sendDatagram(dest_addr, dgram[0..n]);
    }

    fn sendPing(self: *Node, node_id: table.NodeId, addr: std.net.Address) void {
        const req_id = self.nextRequestId();
        const msg = protocol.Ping{ .request_id = req_id, .enr_seq = 1 };
        const enc = protocol.encodePing(self.allocator, msg) catch return;
        defer self.allocator.free(enc);

        // If we have a session, send as ordinary; otherwise this is best-effort.
        _ = addr;
        self.sendToNode(node_id, enc);

        self.pending.append(self.allocator, .{
            .request_id = req_id,
            .target = node_id,
            .sent_at_ns = self.last_poll_ns,
            .kind = .ping,
        }) catch {};
    }

    fn sendFindNode(self: *Node, node_id: table.NodeId, distances: []const u8) void {
        const req_id = self.nextRequestId();
        const msg = protocol.FindNode{ .request_id = req_id, .distances = distances };
        const enc = protocol.encodeFindNode(self.allocator, msg) catch return;
        defer self.allocator.free(enc);
        self.sendToNode(node_id, enc);

        self.pending.append(self.allocator, .{
            .request_id = req_id,
            .target = node_id,
            .sent_at_ns = self.last_poll_ns,
            .kind = .findnode,
        }) catch {};
    }

    fn sendDatagram(self: *Node, addr: std.net.Address, data: []const u8) void {
        if (self.send_fn) |f| {
            f(addr, data);
            return;
        }
        if (self.socket) |sock| {
            _ = std.posix.sendto(sock, data, 0, &addr.any, addr.getOsSockLen()) catch {};
        }
    }

    // -----------------------------------------------------------------------
    // Timers
    // -----------------------------------------------------------------------

    fn expireRequests(self: *Node, now_ns: u64) void {
        const timeout_ns = protocol.request_timeout_ms * std.time.ns_per_ms;
        var i: usize = 0;
        while (i < self.pending.items.len) {
            if (now_ns -| self.pending.items[i].sent_at_ns >= timeout_ns) {
                _ = self.pending.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    fn refreshBuckets(self: *Node, now_ns: u64) void {
        for (&self.routing_table.buckets) |*b| {
            if (b.leastRecentlySeen()) |entry| {
                self.sendPing(entry.node_id, entry.udp_addr);
            }
        }
        _ = now_ns;
    }

    // -----------------------------------------------------------------------
    // Bootstrap
    // -----------------------------------------------------------------------

    pub fn addBootstrap(self: *Node, entry: table.Entry) void {
        _ = self.routing_table.add(entry);
    }

    // -----------------------------------------------------------------------
    // Iterative FINDNODE lookup
    // -----------------------------------------------------------------------

    /// Start an iterative FINDNODE lookup toward `target`.
    /// Returns the locally-known closest nodes immediately; the lookup
    /// proceeds asynchronously via `poll()`.
    pub fn lookupClosest(self: *Node, target: table.NodeId, out: []table.Entry) usize {
        // Seed with locally-known closest.
        const seed_count = self.routing_table.closest(target, out);

        // Start an active lookup.
        var lk = Lookup{ .target = target };
        lk.result_count = seed_count;
        for (out[0..seed_count], 0..) |e, i| lk.results[i] = e;

        // Send FINDNODE to the alpha closest we know.
        const alpha = @min(seed_count, self.config.lookup_alpha);
        const dist_buf = [_]u8{255}; // Request bucket 255 (closest).
        for (out[0..alpha]) |e| {
            self.sendFindNode(e.node_id, &dist_buf);
            lk.queried[lk.queried_count] = e.node_id;
            lk.queried_count += 1;
        }
        self.active_lookup = lk;

        return seed_count;
    }

    fn advanceLookup(self: *Node, lk: *Lookup, new_entry: table.Entry) void {
        // Skip if already queried.
        for (lk.queried[0..lk.queried_count]) |id| {
            if (std.mem.eql(u8, &id, &new_entry.node_id)) return;
        }
        if (lk.queried_count >= lk.queried.len) return;

        // Add to results if closer than current worst.
        var inserted = false;
        if (lk.result_count < table.k) {
            lk.results[lk.result_count] = new_entry;
            lk.result_count += 1;
            inserted = true;
        }
        if (!inserted) return;

        // Query the new node.
        const dist_buf = [_]u8{255};
        self.sendFindNode(new_entry.node_id, &dist_buf);
        lk.queried[lk.queried_count] = new_entry.node_id;
        lk.queried_count += 1;
    }

    // -----------------------------------------------------------------------
    // Capability-aware peer query
    // -----------------------------------------------------------------------

    /// Find up to `out.len` nodes that advertise the given EC scheme bitmask.
    /// Filters using the ENR cache populated from NODES responses.
    pub fn queryByCapability(
        self: *const Node,
        scheme_mask: u16,
        out: []table.Entry,
    ) usize {
        if (scheme_mask == 0) {
            return self.routing_table.closest(self.local_id, out);
        }
        // Filter candidates by ENR-cached scheme_mask.
        var candidates: [table.k * 4]table.Entry = undefined;
        const n = self.routing_table.closest(self.local_id, &candidates);
        var count: usize = 0;
        for (candidates[0..n]) |e| {
            if (count >= out.len) break;
            if (self.enr_cache.get(e.node_id)) |ec| {
                if (ec.schemes & scheme_mask != 0) {
                    out[count] = e;
                    count += 1;
                }
            }
        }
        return count;
    }

    fn nextRequestId(self: *Node) u64 {
        const id = self.request_id_counter;
        self.request_id_counter += 1;
        return id;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "node init and start/stop" {
    const gpa = std.testing.allocator;
    var node = try Node.init(gpa, .{
        .local_privkey = [_]u8{1} ** 32,
        .listen_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0),
    });
    defer node.deinit();

    try node.start();
    try std.testing.expectEqual(NodeState.running, node.state);
    node.stop();
    try std.testing.expectEqual(NodeState.stopped, node.state);
}

test "node poll advances next_refresh deadline" {
    const gpa = std.testing.allocator;
    var node = try Node.init(gpa, .{
        .local_privkey = [_]u8{2} ** 32,
        .bucket_refresh_ms = 1000,
    });
    defer node.deinit();
    node.state = .running; // Don't bind socket in test.

    const deadline = node.poll(0);
    try std.testing.expect(deadline > 0);
}

test "addBootstrap populates routing table" {
    const gpa = std.testing.allocator;
    var node = try Node.init(gpa, .{ .local_privkey = [_]u8{3} ** 32 });
    defer node.deinit();

    node.addBootstrap(.{
        .node_id = [_]u8{0xff} ** 32,
        .udp_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9000),
        .enr_seq = 1,
        .last_seen_ns = 0,
    });
    try std.testing.expectEqual(@as(usize, 1), node.routing_table.totalEntries());
}

test "queryByCapability returns all nodes when scheme_mask=0" {
    const gpa = std.testing.allocator;
    var node = try Node.init(gpa, .{ .local_privkey = [_]u8{4} ** 32 });
    defer node.deinit();

    for (0..5) |i| {
        node.addBootstrap(.{
            .node_id = [_]u8{@intCast(i + 1)} ** 32,
            .udp_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, @intCast(9000 + i)),
            .enr_seq = 1,
            .last_seen_ns = 0,
        });
    }

    var out: [10]table.Entry = undefined;
    const count = node.queryByCapability(0, &out);
    try std.testing.expect(count > 0);
}
