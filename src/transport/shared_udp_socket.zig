//! A single UDP socket shared between the discv5 discovery layer and the QUIC transport.
//!
//! Both protocols are UDP-based and must co-exist on the same port.  This module
//! owns the bound socket fd, drives the receive loop, and demultiplexes each datagram:
//!
//!   1. Offer the packet to discv5 via `Node.injectDatagram`.
//!      discv5 validates the AES-masked header; non-discv5 packets produce a decode
//!      error and `injectDatagram` returns `false`.
//!   2. If discv5 rejected the packet, forward it to lsquic via `feedPacket`.
//!
//! After draining all pending packets call `processEngineOnly` so lsquic can run
//! its internal timers and flush any queued outbound QUIC frames.

const std = @import("std");
const posix = std.posix;
const discv5_node = @import("../discovery/discv5/node.zig");
const eth_ec_quic = @import("eth_ec_quic.zig");

const max_datagram_len = 1500;

pub const SharedUdpSocket = struct {
    sock: posix.socket_t,
    local_addr: std.net.Address,

    /// Bind a new UDP socket to `0.0.0.0:port` (port 0 = OS-assigned).
    pub fn bind(port: u16) !SharedUdpSocket {
        const addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
        const sock = try posix.socket(
            addr.any.family,
            posix.SOCK.DGRAM | posix.SOCK.NONBLOCK,
            posix.IPPROTO.UDP,
        );
        errdefer posix.close(sock);

        const reuse: c_int = 1;
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuse));
        try posix.bind(sock, &addr.any, addr.getOsSockLen());

        var actual: posix.sockaddr = undefined;
        var actual_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        try posix.getsockname(sock, &actual, &actual_len);

        return .{
            .sock = sock,
            .local_addr = .{ .any = actual },
        };
    }

    pub fn deinit(self: *SharedUdpSocket) void {
        posix.close(self.sock);
    }

    /// The underlying file descriptor — pass to `discv5_node.startFromFd` and
    /// `eth_ec_quic.listenOnFd` so both protocols use the same socket.
    pub fn fd(self: *const SharedUdpSocket) posix.socket_t {
        return self.sock;
    }

    /// The address the socket is bound to (with the actual port when 0 was requested).
    pub fn localAddr(self: *const SharedUdpSocket) std.net.Address {
        return self.local_addr;
    }

    pub fn localPort(self: *const SharedUdpSocket) u16 {
        return self.local_addr.getPort();
    }

    /// Block until the socket has at least one readable datagram or `timeout_ms` elapses.
    /// Returns `true` when data is available.
    pub fn waitReadable(self: *SharedUdpSocket, timeout_ms: u32) !bool {
        var pfd = [_]posix.pollfd{.{
            .fd = self.sock,
            .events = posix.POLL.IN,
            .revents = 0,
        }};
        const n = try posix.poll(&pfd, @intCast(timeout_ms));
        return n > 0 and (pfd[0].revents & posix.POLL.IN) != 0;
    }

    /// Drain all pending datagrams and route each to either `discv5_node` or the QUIC
    /// listener.  `quic_listener` may be `null` during startup before QUIC is initialised;
    /// in that case unrecognised packets are silently dropped.
    pub fn routePackets(
        self: *SharedUdpSocket,
        discv5: *discv5_node.Node,
        quic_listener: ?*eth_ec_quic.EthEcQuicListener,
    ) void {
        var buf: [max_datagram_len]u8 = undefined;
        var from: posix.sockaddr = undefined;
        var from_len: posix.socklen_t = @sizeOf(posix.sockaddr);

        while (true) {
            const n = posix.recvfrom(
                self.sock,
                &buf,
                posix.MSG.DONTWAIT,
                &from,
                &from_len,
            ) catch break; // EAGAIN → no more datagrams

            const peer = std.net.Address{ .any = from };

            if (!discv5.injectDatagram(buf[0..n], peer)) {
                // Not a discv5 packet — forward to QUIC.
                if (quic_listener) |ql| {
                    eth_ec_quic.feedPacket(ql, buf[0..n], peer, self.local_addr);
                }
            }
        }
    }
};
