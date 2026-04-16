//! Stable error names aligned with ethp2p [`broadcast/errors.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/errors.go).

pub const Error = error{
    EngineClosed,
    ChannelExists,
    ChannelNotFound,
    PeerExists,
    PeerNotFound,
    InvalidMessage,
    ProtocolMismatch,
    UnexpectedMsgType,
    AlreadySubscribed,
    UnbufferedSubscription,
    ChunkMarshal,
    ChunkPeerGone,
    ChunkSlotFull,
    ChunkWriteFail,
    ChunkCancelled,
    SessionClosing,
};

/// Mirrors `ChunkProcessError` in the reference (peer + channel + message + wrapped cause).
pub fn ChunkProcessError(comptime PeerId: type, comptime ChannelId: type, comptime MessageId: type) type {
    return struct {
        peer: PeerId,
        channel_id: ChannelId,
        message_id: MessageId,
        err: anyerror,
    };
}
