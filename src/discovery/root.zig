//! ethp2p discovery layer.
//!
//! Provides discv5-based peer discovery, ENR handling, and duty-aware peer
//! selection feeding into the QUIC transport (`transport.eth_ec_quic`).
//!
//! Module layout:
//!
//!   enr/
//!     enr.zig       ENR decode/encode (RLP, EIP-778)
//!     standard.zig  Standard ENR field decoders
//!     ethp2p.zig    eth-ec capability field, custody columns, geo-hint
//!
//!   discv5/
//!     table.zig     256-bucket Kademlia routing table (k=16)
//!     crypto.zig    AES-128-GCM, HKDF-SHA256, secp256k1 (std.crypto)
//!     packet.zig    Ordinary / WHOAREYOU / Handshake packet codec
//!     session.zig   Per-peer session key state
//!     protocol.zig  PING / PONG / FINDNODE / NODES / TALKREQ / TALKRES
//!     node.zig      Drive loop, bootstrap, capability query
//!
//!   peering/
//!     score.zig     RTT-first composite scoring with time decay
//!     duty.zig      Duty types, slot capacities, selection requirements
//!     table.zig     Selfish + altruistic peer table segments
//!     pool.zig      Connection pool: hot / warm / cold warmth states
//!     warmup.zig    Slot-phase-aware 0-RTT warming scheduler

pub const enr = @import("enr/enr.zig");
pub const enr_std = @import("enr/standard.zig");
pub const enr_ethp2p = @import("enr/ethp2p.zig");

pub const discv5_table = @import("discv5/table.zig");
pub const discv5_crypto = @import("discv5/crypto.zig");
pub const discv5_packet = @import("discv5/packet.zig");
pub const discv5_session = @import("discv5/session.zig");
pub const discv5_protocol = @import("discv5/protocol.zig");
pub const discv5_node = @import("discv5/node.zig");

pub const peering_score = @import("peering/score.zig");
pub const peering_duty = @import("peering/duty.zig");
pub const peering_table = @import("peering/table.zig");
pub const peering_pool = @import("peering/pool.zig");
pub const peering_warmup = @import("peering/warmup.zig");
pub const peer_manager = @import("peer_manager.zig");

// Convenience re-exports.
pub const RoutingTable = discv5_table.RoutingTable;
pub const Node = discv5_node.Node;
pub const PeerTable = peering_table.PeerTable;
pub const Pool = peering_pool.Pool;
pub const Scheduler = peering_warmup.Scheduler;
pub const Score = peering_score.Score;
pub const DutyKind = peering_duty.DutyKind;
pub const SlotPhase = peering_warmup.SlotPhase;
pub const currentPhase = peering_warmup.currentPhase;
pub const EthEcField = enr_ethp2p.EthEcField;

test {
    _ = @import("enr/enr.zig");
    _ = @import("enr/standard.zig");
    _ = @import("enr/ethp2p.zig");
    _ = @import("discv5/table.zig");
    _ = @import("discv5/crypto.zig");
    _ = @import("discv5/packet.zig");
    _ = @import("discv5/session.zig");
    _ = @import("discv5/protocol.zig");
    _ = @import("discv5/node.zig");
    _ = @import("peering/score.zig");
    _ = @import("peering/duty.zig");
    _ = @import("peering/table.zig");
    _ = @import("peering/pool.zig");
    _ = @import("peering/warmup.zig");
    _ = @import("peer_manager.zig");
}
