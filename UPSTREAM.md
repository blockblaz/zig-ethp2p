# Upstream alignment

This repository tracks **[ethp2p](https://github.com/ethp2p/ethp2p)**.

## Zig toolchain

`build.zig.zon` `minimum_zig_version` must match the `ZIG_VERSION` environment variable in [`.github/workflows/ci.yml`](.github/workflows/ci.yml). CI fails the job if they differ, so bump both when raising the supported Zig release.

## Pinned revision

The vendored `.proto` files and golden test vectors were checked against reference commit:

`db6e9417d0bbab9ded28aa3053211cdecff402ac`

Changes since the previous pin (`125bdaa`):

- `sim/strategy_gossipsub.go` (`db6e941`): gossipsub params aligned with Prysm
  (`beacon-chain/p2p/pubsub.go`).
  - `HistoryLength`: 1000 → 6; `HistoryGossip`: 1000 → 3.
  - Added `StrictNoSign` + `NoAuthor`: messages carry no `from`/`seqno`/`signature`/`key` fields.
  - Added `PeerOutboundQueueSize(600)`, `ValidateQueueSize(600)`.
  - **zig-ethp2p impact**: none. `FanoutMesh` is an abstract in-process model with no message
    cache. `GossipMessageRef` already defaults `from`/`seqno`/`signature`/`key` to `null`; all
    tests use messages with only `topic` and `data` set — matching `StrictNoSign`/`NoAuthor`.
    Queue sizes have no Zig equivalent.

When updating:

1. Diff `proto/*.proto` against:
   - `broadcast/pb/broadcast.proto`
   - `protocol/pb/protocol.proto`
   - `broadcast/rs/pb/rs.proto`
   - `go-libp2p-pubsub/pb/rpc.proto` (for `proto/gossipsub_rpc.proto` field numbers; `sim/gossipsub_rpc_pb.zig` implements `RPC` 1–3 and **10** (`partial` / `PartialMessagesExtension`), full `ControlMessage`, varint length-prefixed framing; other extension field numbers are skipped on decode. `sim/gossipsub_rpc_host.zig` is an in-process duplex for framed `RPC`, not a libp2p transport.)
2. Run `zig build test` (golden bytes must still match `google.golang.org/protobuf` output from that tree).
3. Bump the commit hash in this file.

## QUIC / UDP transport

`src/transport/eth_ec_quic.zig` mirrors **ALPN** `eth-ec-broadcast` and high-level **quic-go-style** limits from ethp2p `sim/host.go`. With **`-Denable-quic`**, lsquic + BoringSSL is linked via `vendor/lsquic_zig`.

### Why raw QUIC and why unidirectional streams

**Why raw QUIC?** Direct access to QUIC's built-in multiplexing, per-stream flow control, congestion control, and RTT measurements — without adding another framing layer.

**Why unidirectional streams?** P2P protocols have no client/server notion; both peers are equal and can try to open a stream to each other simultaneously. With bidirectional streams that creates a *simultaneous open* ambiguity that must be resolved in-band. Unidirectional streams eliminate the ambiguity by design: each peer opens its own send stream independently, and there is no question about which side "owns" the stream. Opening streams in QUIC is cheap (no extra round-trip), so the cost of using two half-streams instead of one full-stream is negligible.

Bidirectional streams are viable when the protocol has a clear initiator (e.g. HTTP, where only the client opens streams). ethp2p deliberately chose UNI streams to keep the peer state machine stateless with respect to stream negotiation.

### UNI stream alignment (issue #28)

The ethp2p reference uses **unidirectional** QUIC streams for all application protocols:

- `peer.go` `handshake()`: both sides call `conn.OpenUniStream()` for the BCAST control stream (IDs 2/3, 6/7, …)
- `peer_ctrl.go` `handleSessionOpen`, `doSendChunk`: `conn.OpenUniStream()` for SESS and CHUNK streams
- `peer_in.go` `runAcceptLoop`: `conn.AcceptUniStream()` for all inbound streams

Zig alignment:

- `lsquic_quic_shim.zig` detects stream type via `lsquic_stream_id() & 0x2` (bit 1 = unidirectional per RFC 9000 §2.1)
- `incoming_uni_streams` queue holds peer-initiated UNI streams; `tryAcceptIncomingUniStream` pops them
- `streamMakeUni` opens an outgoing UNI stream via `lsquic_conn_make_uni_stream`
- `eth_ec_quic_peer.zig` sketches the `PeerConn` poll-driven state machine (handshake + accept-loop)

### lsquic vendor patch

lsquic 4.3 has no public API for user-initiated outgoing unidirectional streams (`lsquic_conn_make_stream` always creates bidirectional streams). The internal `create_uni_stream_out` function in `lsquic_full_conn_ietf.c` is `static`.

Fix: `vendor/lsquic_zig/build.zig` runs `vendor/lsquic_zig/patch_uni.sh` as a build step. The script:
1. Removes `static` from `create_uni_stream_out` in a patched copy of `lsquic_full_conn_ietf.c`
2. Appends a public `lsquic_conn_make_uni_stream(lsquic_conn_t *)` wrapper at the end of the file

The public declaration lives in `vendor/lsquic_zig/lsquic_ethp2p_ext.h`. The upstream source file is untouched.

### libp2p boundary

The ethp2p `sim/` QUIC transport is illustrative. Production deployments layer **libp2p** on top (Noise handshake, multistream-select, Yamux multiplexer, identify protocol). That layer is out of scope for `zig-ethp2p`; zeam handles it via **rust-libp2p**.

## EC schemes (issue [#14](https://github.com/ch4r10t33r/zig-ethp2p/issues/14))

`src/layer/ec_scheme.zig` defines `EcSchemeKind` and the `"reed-solomon"` string aligned with `broadcast/rs/types.go` `NewScheme`. Only Reed–Solomon is implemented end-to-end; RLNC needs spec’d preamble / chunk types and a strategy implementation before wire changes.

## Abstract mesh tests

`src/sim/rs_mesh.zig` runs the same RS **settings and graph topologies** as `sim/scenario_test.go` (`TestNetwork` RS / RS-ChunkLen) against `layer.RsStrategy` in-process (no libp2p, no Go simnet). Adjacency and per-peer stats are **heap-allocated** (`MaxMeshNodes` cap). `MeshParams.partition` drops selected undirected links for an initial round range (no chunks / routing across them), then restores them—this matches the **intent** of ethp2p CI’s `TestNodeReconnection` name in the `simnet-rs` job (that test does not exist on ethp2p `main` today). `zig build test` and `zig build simtest` both execute these cases. With `ZIG_ETHP2P_STRESS=1` (see `zig build test-stress`), extra cases use higher round budgets and add **8- and 16-node** ring graphs beyond the Go file’s largest fixed topology.

## Specifications

Normative docs: [ethp2p/specs](https://github.com/ethp2p/ethp2p/tree/main/specs) (architecture `001-ethp2p`, broadcast `002`–`004`).

## Wire compatibility

- **Length-prefixed frames** match `broadcast/wire.go` (`MaxFrameSize`, big-endian `uint32` length, then payload).
- **Stream opener** is a **single byte** (`protocol/protocol.go` `WriteSelector` / `ReadSelector`), equal to the `Protocol` enum value. The `Selector` protobuf in `protocol.proto` describes that enum for codegen; the reference does not length-prefix or protobuf-encode the selector on the wire.
- **CHUNK streams** (`broadcast/peer_ctrl.go` `doSendChunk`, `peer_in.go` `processChunk`): `0x03`, then length-framed `Chunk.Header`, then exactly `data_length` bytes of payload (not framed).
- **BCAST / SESS** high-level open helpers mirror `peer.go` / `peer_ctrl.go` / `peer_in.go` (see `wire/bcast_stream.zig`, `wire/sess_stream.zig`).
- **Protobuf field numbers** for framed messages match the `.proto` definitions; tests include hex from the Go reference.
