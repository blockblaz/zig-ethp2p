//! Broadcast-layer enums and aliases aligned with ethp2p `broadcast/types.go`.

pub const ChunkHandle = u64;

pub const protocol_v1: u32 = 1;

pub const Verdict = enum(u8) {
    accepted = 0,
    redundant = 1,
    decoding = 2,
    surplus = 3,
    invalid = 4,
    pending = 5,
};
