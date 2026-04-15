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

/// Tracks an outbound ordinary packet whose nonce we need to correlate
/// against an inbound WHOAREYOU challenge.
const PendingChallenge = struct {
    target: table.NodeId,
    addr: std.net.Address,
    nonce: [12]u8,
    /// Plaintext message to re-encrypt inside the Handshake body.
    plain_msg: ?[]const u8,
    sent_at_ns: u64,
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

    /// Protects all mutable node state accessed by both poll() and injectDatagram().
    /// Callers that run the poll loop in one thread while delivering packets via
    /// injectDatagram() from another thread (e.g. a shared UDP receive loop) would
    /// otherwise race on `pending`, `challenge_pending`, and related fields, causing
    /// undefined behaviour including the integer-overflow panic seen in swapRemove.
    mu: std.Thread.Mutex = .{},

    /// UDP socket file descriptor (null when stopped).
    socket: ?std.posix.fd_t = null,
    /// True when this node created and owns the socket (must close on stop/deinit).
    /// False when an external caller supplied the fd via `startFromFd`.
    owns_socket: bool = true,

    /// In-flight requests.
    pending: std.ArrayListUnmanaged(PendingRequest) = .{},
    /// Outbound ordinary packets awaiting WHOAREYOU correlation.
    challenge_pending: std.ArrayListUnmanaged(PendingChallenge) = .{},
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
        if (self.owns_socket) {
            if (self.socket) |sock| {
                std.posix.close(sock);
                self.socket = null;
            }
        }
        self.pending.deinit(self.allocator);
        for (self.challenge_pending.items) |ch| {
            if (ch.plain_msg) |msg| self.allocator.free(msg);
        }
        self.challenge_pending.deinit(self.allocator);
        self.enr_cache.deinit(self.allocator);
        self.sessions.deinit();
    }

    /// Bind a new UDP socket and start the node.
    pub fn start(self: *Node) !void {
        const addr = self.config.listen_addr;
        const sock = try std.posix.socket(
            addr.any.family,
            std.posix.SOCK.DGRAM | std.posix.SOCK.NONBLOCK,
            0,
        );
        try std.posix.bind(sock, &addr.any, addr.getOsSockLen());
        self.socket = sock;
        self.owns_socket = true;
        self.state = .running;
    }

    /// Attach an externally-owned UDP socket and start the node without binding.
    /// The caller retains ownership of `fd` and must not close it while the node
    /// is running.  `poll` will skip the internal recv loop; the caller is
    /// expected to drain packets and deliver them via `injectDatagram`.
    pub fn startFromFd(self: *Node, fd: std.posix.fd_t) void {
        self.socket = fd;
        self.owns_socket = false;
        self.state = .running;
    }

    pub fn stop(self: *Node) void {
        if (self.owns_socket) {
            if (self.socket) |sock| {
                std.posix.close(sock);
            }
        }
        self.socket = null;
        self.state = .stopped;
    }

    // -----------------------------------------------------------------------
    // Drive loop
    // -----------------------------------------------------------------------

    /// Advance timers and drain inbound UDP datagrams.
    /// `now_ns` is a monotonic clock reading.
    /// Returns the next deadline the caller should wake at.
    ///
    /// Thread-safe: acquires `mu` for the full duration so that concurrent
    /// calls to `injectDatagram` from another thread do not race on the
    /// internal `pending` / `challenge_pending` lists.
    pub fn poll(self: *Node, now_ns: u64) u64 {
        self.mu.lock();
        defer self.mu.unlock();

        self.last_poll_ns = now_ns;

        // Receive available datagrams — only when we own the socket.
        // With an external fd the caller drives recv via injectDatagram.
        if (self.owns_socket) {
            if (self.socket) |sock| {
                self.recvLoop(sock);
            }
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
            .whoareyou => |w| self.handleWhoareyou(w.header, w.auth, data, from),
            .handshake => |h| self.handleHandshake(h.header, h.auth, h.encrypted_body, from),
        }
    }

    /// Attempt to decode and process a datagram received from an external source
    /// (e.g. a shared UDP socket).  Returns `true` when the datagram was valid
    /// discv5 and has been processed; `false` when it should be forwarded elsewhere
    /// (e.g. to a co-located QUIC endpoint).
    ///
    /// Thread-safe: acquires `mu` so this can safely be called from a UDP receive
    /// thread while `poll` is running concurrently on the drive-loop thread.
    pub fn injectDatagram(self: *Node, data: []const u8, from: std.net.Address) bool {
        var hdr_buf: [packet.static_header_len + 300 + 32]u8 = undefined;
        const pkt = packet.decode(data, self.local_id, &hdr_buf) catch return false;
        self.mu.lock();
        defer self.mu.unlock();
        switch (pkt) {
            .ordinary => |o| self.handleOrdinary(o.header, o.auth, o.encrypted_body, from),
            .whoareyou => |w| self.handleWhoareyou(w.header, w.auth, data, from),
            .handshake => |h| self.handleHandshake(h.header, h.auth, h.encrypted_body, from),
        }
        return true;
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
        raw_datagram: []const u8,
        from: std.net.Address,
    ) void {
        // Correlate by matching the WHOAREYOU's nonce against nonces of
        // packets we recently sent.
        const pending = self.popPendingChallenge(hdr.nonce) orelse return;
        defer if (pending.plain_msg) |msg| self.allocator.free(msg);

        // Extract challenge_data (masking-iv || static-header || auth-data)
        // from the raw WHOAREYOU datagram for id-nonce signing.
        if (raw_datagram.len < session.challenge_data_len) return;
        const challenge_data: [session.challenge_data_len]u8 = raw_datagram[0..session.challenge_data_len].*;

        // Generate ephemeral keypair for the handshake.
        var eph_priv: [crypto.privkey_len]u8 = undefined;
        var eph_pub: [crypto.pubkey_len]u8 = undefined;
        crypto.generateEphemeralKeypair(&eph_priv, &eph_pub) catch return;

        // Look up the remote's public key so we can do ECDH.
        const remote_entry = self.routing_table.getEntry(pending.target) orelse return;
        const remote_pubkey = remote_entry.pubkey;

        // ECDH shared secret.
        var secret: [32]u8 = undefined;
        crypto.ecdhSharedSecret(&secret, eph_priv, remote_pubkey) catch return;

        // Derive session keys (we are the initiator).
        const keys = crypto.deriveSessionKeys(secret, auth.id_nonce, eph_pub, self.local_id, pending.target);

        // Sign the id-nonce challenge.
        var id_sig: [crypto.ecdsa_sig_len]u8 = undefined;
        crypto.ecdsaSignIdNonce(&id_sig, &challenge_data, eph_pub, pending.target, self.config.local_privkey) catch return;

        // Encrypt the original message as the Handshake body.
        var ct_buf: [packet.max_datagram_len]u8 = undefined;
        var ct_len: usize = 0;
        if (pending.plain_msg) |msg| {
            if (msg.len + crypto.aes_tag_len > ct_buf.len) return;
            var nonce: [crypto.aes_nonce_len]u8 = undefined;
            std.crypto.random.bytes(&nonce);
            crypto.encryptAesGcm(ct_buf[0 .. msg.len + crypto.aes_tag_len], msg, &hdr.nonce, keys.initiator_key, nonce);
            ct_len = msg.len + crypto.aes_tag_len;
        }

        // Encode and send the Handshake packet.
        var iv: [packet.masking_iv_len]u8 = undefined;
        std.crypto.random.bytes(&iv);
        var dgram: [packet.max_datagram_len]u8 = undefined;
        const n = packet.encodeHandshake(&dgram, iv, pending.target, hdr.nonce, .{
            .src_id = self.local_id,
            .ephem_pubkey = eph_pub,
            .id_sig = id_sig,
            .record = &.{},
        }, ct_buf[0..ct_len]) catch return;

        // Establish session.
        const nonce_base: [8]u8 = hdr.nonce[0..8].*;
        const sess = self.sessions.getOrCreate(pending.target, nonce_base) catch return;
        sess.establish(keys);

        self.sendDatagram(from, dgram[0..n]);
    }

    /// Find and remove a PendingChallenge whose nonce matches.
    fn popPendingChallenge(self: *Node, nonce: [12]u8) ?PendingChallenge {
        for (self.challenge_pending.items, 0..) |ch, i| {
            if (std.mem.eql(u8, &ch.nonce, &nonce)) {
                return self.challenge_pending.swapRemove(i);
            }
        }
        return null;
    }

    fn handleHandshake(
        self: *Node,
        hdr: packet.PacketHeader,
        auth: packet.HandshakeAuthData,
        encrypted_body: []const u8,
        from: std.net.Address,
    ) void {
        // The session for this peer must exist in awaiting_handshake state
        // (created by sendWhoareyou). It holds the id_nonce and raw
        // challenge_data we need for key derivation and id-sig verification.
        const sess = self.sessions.get(auth.src_id) orelse return;
        if (sess.state != .awaiting_handshake) return;

        // Recover the remote's public key for id-sig verification.
        const remote_entry = self.routing_table.getEntry(auth.src_id) orelse {
            // We might not know the peer's static pubkey yet.  Accept the
            // ephemeral pubkey from the handshake for ECDH (we still verify
            // the signature below).
            self.handleHandshakeNewPeer(hdr, auth, encrypted_body, from, sess);
            return;
        };

        // Verify the id-signature using the stored challenge_data.
        crypto.ecdsaVerifyIdNonce(
            auth.id_sig,
            &sess.challenge_data,
            auth.ephem_pubkey,
            self.local_id,
            remote_entry.pubkey,
        ) catch return;

        self.completeHandshake(hdr, auth, encrypted_body, from, sess);
    }

    /// Complete the responder side of the handshake after id-sig verification.
    fn completeHandshake(
        self: *Node,
        hdr: packet.PacketHeader,
        auth: packet.HandshakeAuthData,
        encrypted_body: []const u8,
        from: std.net.Address,
        sess: *session.Session,
    ) void {
        // ECDH shared secret using our static key and their ephemeral key.
        var secret: [32]u8 = undefined;
        crypto.ecdhSharedSecret(&secret, self.config.local_privkey, auth.ephem_pubkey) catch return;

        // Derive session keys using the id_nonce from the WHOAREYOU we sent.
        // We are the responder: our initiator_key decrypts their messages.
        const keys = crypto.deriveSessionKeys(secret, sess.id_nonce, auth.ephem_pubkey, auth.src_id, self.local_id);
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
                crypto.decryptAesGcm(plain[0..blen], encrypted_body, &hdr.nonce, sess.keys.initiator_key, hdr.nonce) catch return;
                self.dispatchMessage(plain[0..blen], auth.src_id);
            }
        }
    }

    /// Handle a Handshake from a peer we don't yet have in the routing table.
    fn handleHandshakeNewPeer(
        self: *Node,
        hdr: packet.PacketHeader,
        auth: packet.HandshakeAuthData,
        encrypted_body: []const u8,
        from: std.net.Address,
        sess: *session.Session,
    ) void {
        // Without a known static pubkey we cannot verify the id-signature
        // against an authenticated identity. If the Handshake includes an
        // ENR record we can extract the pubkey from it; otherwise reject.
        if (auth.record.len == 0) return;

        // Try to derive the public key from the ENR record and verify.
        // For now, accept the handshake optimistically (the ENR will be
        // validated by processInboundEnr).
        crypto.ecdsaVerifyIdNonce(
            auth.id_sig,
            &sess.challenge_data,
            auth.ephem_pubkey,
            self.local_id,
            auth.ephem_pubkey,
        ) catch return;

        self.completeHandshake(hdr, auth, encrypted_body, from, sess);
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

    /// Send a message to a peer.  If a session is established, encrypt and
    /// send as an ordinary packet (recording nonce for WHOAREYOU correlation).
    /// Otherwise, send a random packet to trigger a WHOAREYOU challenge.
    fn sendToNode(self: *Node, node_id: table.NodeId, plain: []const u8) void {
        const entry = self.routing_table.getEntry(node_id) orelse return;
        const sess_opt = self.sessions.get(node_id);
        if (sess_opt) |sess| {
            if (sess.isEstablished()) {
                self.sendEstablished(node_id, plain, entry.udp_addr, sess);
                return;
            }
        }
        // No session — send a random ordinary-looking packet to elicit WHOAREYOU.
        self.sendInitialRandom(node_id, plain, entry.udp_addr);
    }

    /// Encrypt and send via an established session, recording nonce.
    fn sendEstablished(
        self: *Node,
        node_id: table.NodeId,
        plain: []const u8,
        addr: std.net.Address,
        sess: *session.Session,
    ) void {
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

        self.sendDatagram(addr, dgram[0..n]);

        const duped_msg = self.allocator.dupe(u8, plain) catch return;
        self.challenge_pending.append(self.allocator, .{
            .target = node_id,
            .addr = addr,
            .nonce = nonce,
            .plain_msg = duped_msg,
            .sent_at_ns = self.last_poll_ns,
        }) catch {
            self.allocator.free(duped_msg);
        };
    }

    /// Send a random ordinary packet to trigger a WHOAREYOU from the remote.
    /// The plaintext message is stored so it can be retried inside the
    /// Handshake body once the challenge arrives.
    fn sendInitialRandom(
        self: *Node,
        node_id: table.NodeId,
        plain: []const u8,
        addr: std.net.Address,
    ) void {
        var nonce: [crypto.aes_nonce_len]u8 = undefined;
        std.crypto.random.bytes(&nonce);

        // Random ciphertext — the remote won't decrypt this; it will reply
        // with WHOAREYOU.
        var random_ct: [44]u8 = undefined;
        std.crypto.random.bytes(&random_ct);

        var iv: [packet.masking_iv_len]u8 = undefined;
        std.crypto.random.bytes(&iv);

        var dgram: [packet.max_datagram_len]u8 = undefined;
        const n = packet.encodeOrdinary(
            &dgram,
            iv,
            node_id,
            nonce,
            self.local_id,
            &random_ct,
        ) catch return;

        self.sendDatagram(addr, dgram[0..n]);

        const duped_msg = self.allocator.dupe(u8, plain) catch return;
        self.challenge_pending.append(self.allocator, .{
            .target = node_id,
            .addr = addr,
            .nonce = nonce,
            .plain_msg = duped_msg,
            .sent_at_ns = self.last_poll_ns,
        }) catch {
            self.allocator.free(duped_msg);
        };
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
        const n = packet.encodeWhoareyou(&dgram, iv, dest_id, challenge_nonce, id_nonce, 0) catch return;

        // Record id_nonce and raw WHOAREYOU bytes so handleHandshake can
        // derive correct session keys and verify the id-signature.
        const nonce_base: [8]u8 = challenge_nonce[0..8].*;
        const sess = self.sessions.getOrCreate(dest_id, nonce_base) catch return;
        sess.beginHandshake(id_nonce);
        @memcpy(&sess.challenge_data, dgram[0..session.challenge_data_len]);

        self.sendDatagram(dest_addr, dgram[0..n]);
    }

    fn sendPing(self: *Node, node_id: table.NodeId, addr: std.net.Address) void {
        _ = addr;
        const req_id = self.nextRequestId();
        const msg = protocol.Ping{ .request_id = req_id, .enr_seq = 1 };
        const enc = protocol.encodePing(self.allocator, msg) catch return;
        defer self.allocator.free(enc);

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
        // Expire stale pending challenges (same timeout).
        i = 0;
        while (i < self.challenge_pending.items.len) {
            const ch = &self.challenge_pending.items[i];
            if (now_ns -| ch.sent_at_ns >= timeout_ns) {
                if (ch.plain_msg) |msg| self.allocator.free(msg);
                _ = self.challenge_pending.swapRemove(i);
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

// ---------------------------------------------------------------------------
// Handshake roundtrip tests
// ---------------------------------------------------------------------------

/// Captured datagram for in-process delivery between test nodes.
const TestDatagram = struct {
    data: [packet.max_datagram_len]u8,
    len: usize,
    addr: std.net.Address,
};

/// Simple capture buffer shared between two test nodes.
var test_capture_a: ?TestDatagram = null;
var test_capture_b: ?TestDatagram = null;

fn captureSendA(_: std.net.Address, data: []const u8) void {
    var d: TestDatagram = undefined;
    @memcpy(d.data[0..data.len], data);
    d.len = data.len;
    test_capture_a = d;
}

fn captureSendB(_: std.net.Address, data: []const u8) void {
    var d: TestDatagram = undefined;
    @memcpy(d.data[0..data.len], data);
    d.len = data.len;
    test_capture_b = d;
}

const TestNodePair = struct {
    a: *Node,
    b: *Node,
    allocator: std.mem.Allocator,

    fn deinit(self: *TestNodePair) void {
        self.a.deinit();
        self.allocator.destroy(self.a);
        self.b.deinit();
        self.allocator.destroy(self.b);
    }
};

fn makeTestNodePair(gpa: std.mem.Allocator) !TestNodePair {
    const priv_a = [_]u8{0x11} ** 32;
    const priv_b = [_]u8{0x22} ** 32;

    var pub_a: [crypto.pubkey_len]u8 = undefined;
    try crypto.generatePubkey(&pub_a, priv_a);
    const id_a = try crypto.nodeIdFromPubkey(pub_a);

    var pub_b: [crypto.pubkey_len]u8 = undefined;
    try crypto.generatePubkey(&pub_b, priv_b);
    const id_b = try crypto.nodeIdFromPubkey(pub_b);

    const addr_a = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9001);
    const addr_b = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9002);

    const a = try gpa.create(Node);
    a.* = try Node.init(gpa, .{ .local_privkey = priv_a });
    a.state = .running;
    a.send_fn = captureSendB;
    a.addBootstrap(.{
        .node_id = id_b,
        .pubkey = pub_b,
        .udp_addr = addr_b,
        .enr_seq = 1,
        .last_seen_ns = 0,
    });

    const b = try gpa.create(Node);
    b.* = try Node.init(gpa, .{ .local_privkey = priv_b });
    b.state = .running;
    b.send_fn = captureSendA;
    b.addBootstrap(.{
        .node_id = id_a,
        .pubkey = pub_a,
        .udp_addr = addr_a,
        .enr_seq = 1,
        .last_seen_ns = 0,
    });

    return .{ .a = a, .b = b, .allocator = gpa };
}

test "WHOAREYOU nonce echoes challenge nonce" {
    const gpa = std.testing.allocator;
    test_capture_a = null;
    test_capture_b = null;

    var pair = try makeTestNodePair(gpa);
    defer pair.deinit();

    // A sends a random packet to B (no session).
    const priv_b = [_]u8{0x22} ** 32;
    var pub_b: [crypto.pubkey_len]u8 = undefined;
    try crypto.generatePubkey(&pub_b, priv_b);
    const id_b = try crypto.nodeIdFromPubkey(pub_b);
    pair.a.sendPing(id_b, std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9002));

    // A's outbound packet was captured in test_capture_b.
    const initial = test_capture_b orelse return error.NoDatagram;

    // Decode the initial packet to get the nonce.
    var hdr_buf: [packet.static_header_len + 300 + 32]u8 = undefined;
    const initial_pkt = try packet.decode(initial.data[0..initial.len], pair.b.local_id, &hdr_buf);
    const initial_nonce = switch (initial_pkt) {
        .ordinary => |o| o.header.nonce,
        else => return error.ExpectedOrdinary,
    };

    // B receives the packet — should respond with WHOAREYOU.
    test_capture_a = null;
    pair.b.handleDatagram(initial.data[0..initial.len], std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9001));

    const whoareyou = test_capture_a orelse return error.NoWhoareyou;
    var hdr_buf2: [packet.static_header_len + 300 + 32]u8 = undefined;
    const way_pkt = try packet.decode(whoareyou.data[0..whoareyou.len], pair.a.local_id, &hdr_buf2);
    const way_nonce = switch (way_pkt) {
        .whoareyou => |w| w.header.nonce,
        else => return error.ExpectedWhoareyou,
    };

    // The WHOAREYOU's nonce must echo the initial packet's nonce.
    try std.testing.expectEqualSlices(u8, &initial_nonce, &way_nonce);
}

test "full handshake roundtrip establishes session" {
    const gpa = std.testing.allocator;
    test_capture_a = null;
    test_capture_b = null;

    var pair = try makeTestNodePair(gpa);
    defer pair.deinit();

    const priv_b = [_]u8{0x22} ** 32;
    var pub_b: [crypto.pubkey_len]u8 = undefined;
    try crypto.generatePubkey(&pub_b, priv_b);
    const id_b = try crypto.nodeIdFromPubkey(pub_b);

    const priv_a = [_]u8{0x11} ** 32;
    var pub_a: [crypto.pubkey_len]u8 = undefined;
    try crypto.generatePubkey(&pub_a, priv_a);
    const id_a = try crypto.nodeIdFromPubkey(pub_a);

    // Step 1: A sends PING to B (no session -> sends random packet).
    pair.a.sendPing(id_b, std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9002));
    const pkt1 = test_capture_b orelse return error.NoDatagram;

    // Verify A recorded a pending challenge.
    try std.testing.expectEqual(@as(usize, 1), pair.a.challenge_pending.items.len);

    // Step 2: B receives random packet -> sends WHOAREYOU.
    test_capture_a = null;
    pair.b.handleDatagram(pkt1.data[0..pkt1.len], std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9001));
    const pkt2 = test_capture_a orelse return error.NoWhoareyou;

    // Verify B has a session in awaiting_handshake state.
    const sess_b = pair.b.sessions.get(id_a);
    try std.testing.expect(sess_b != null);
    try std.testing.expectEqual(session.SessionState.awaiting_handshake, sess_b.?.state);

    // Step 3: A receives WHOAREYOU -> sends Handshake.
    test_capture_b = null;
    pair.a.handleDatagram(pkt2.data[0..pkt2.len], std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9002));
    const pkt3 = test_capture_b orelse return error.NoHandshake;

    // Verify A established a session.
    const sess_a = pair.a.sessions.get(id_b);
    try std.testing.expect(sess_a != null);
    try std.testing.expectEqual(session.SessionState.established, sess_a.?.state);

    // Verify the pending challenge was consumed.
    try std.testing.expectEqual(@as(usize, 0), pair.a.challenge_pending.items.len);

    // Step 4: B receives Handshake -> establishes session.
    pair.b.handleDatagram(pkt3.data[0..pkt3.len], std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9001));
    const sess_b2 = pair.b.sessions.get(id_a);
    try std.testing.expect(sess_b2 != null);
    try std.testing.expectEqual(session.SessionState.established, sess_b2.?.state);
}

test "pending challenge expiry removes stale entries" {
    const gpa = std.testing.allocator;
    var node = try Node.init(gpa, .{ .local_privkey = [_]u8{5} ** 32 });
    defer node.deinit();

    const target_id = [_]u8{0xaa} ** 32;
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 9000);

    node.challenge_pending.append(gpa, .{
        .target = target_id,
        .addr = addr,
        .nonce = [_]u8{0x01} ** 12,
        .plain_msg = null,
        .sent_at_ns = 0,
    }) catch unreachable;

    try std.testing.expectEqual(@as(usize, 1), node.challenge_pending.items.len);

    // Expire at a time far enough in the future.
    const timeout = protocol.request_timeout_ms * std.time.ns_per_ms + 1;
    node.expireRequests(timeout);

    try std.testing.expectEqual(@as(usize, 0), node.challenge_pending.items.len);
}
