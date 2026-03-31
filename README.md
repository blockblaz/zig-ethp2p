# zig-ethp2p

Zig helpers for the wire formats of **[ethp2p](https://github.com/ethp2p/ethp2p)** — the reference implementation is **[github.com/ethp2p/ethp2p](https://github.com/ethp2p/ethp2p)** ([specs directory](https://github.com/ethp2p/ethp2p/tree/main/specs)). This repo tracks that code and the protobuf definitions under `broadcast/pb`, `protocol/pb`, and `broadcast/rs/pb`.

## Implementation status (vs reference)

| Area | Reference location | In zig-ethp2p |
|------|-------------------|---------------|
| Length-prefixed protobuf frames | [`broadcast/wire.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/wire.go) | `wire.frame` |
| Single-byte stream selector | [`protocol/protocol.go`](https://github.com/ethp2p/ethp2p/blob/main/protocol/protocol.go) | `wire.protocol` |
| `Bcast` / `Sess` / `Chunk.Header` protobuf | [`broadcast/pb/broadcast.proto`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/pb/broadcast.proto) | `wire.broadcast` (+ `proto/broadcast.proto`) |
| BCAST stream (handshake + ctrl frames) | [`broadcast/peer.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/peer.go), [`peer_ctrl.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/peer_ctrl.go) | `wire.bcast_stream` |
| SESS stream (open + routing updates) | [`broadcast/peer_ctrl.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/peer_ctrl.go), [`peer_in.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/peer_in.go) | `wire.sess_stream` |
| CHUNK uni-stream | [`broadcast/peer_ctrl.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/peer_ctrl.go) `doSendChunk`, [`peer_in.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/peer_in.go) `processChunk` | `wire.chunk_stream` |
| RS `Preamble` / `ChunkIdent` | [`broadcast/rs/pb`](https://github.com/ethp2p/ethp2p/tree/main/broadcast/rs/pb), [`broadcast/rs/types.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/rs/types.go) | `wire.rs`, `writeRsShardChunk` |
| Protocol version constant | [`broadcast/types.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/types.go) `ProtocolV1` | `wire.constants.protocol_v1` |
| `Verdict` / `ChunkHandle` | [`broadcast/types.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/types.go) | `layer.broadcast_types` |
| RS routing bitmap | [`broadcast/rs/bitmap.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/rs/bitmap.go) | `layer.bitmap` |
| RS `Config` / `initPreamble` | [`broadcast/rs/types.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/rs/types.go) | `layer.rs_init` |
| RS emit planner (fair dispatch heap) | [`broadcast/rs/emit.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/rs/emit.go) | `layer.emit_planner` |
| RS parity encode (klauspost-default matrix) | [klauspost/reedsolomon](https://github.com/klauspost/reedsolomon) via ethp2p RS strategy | `layer.rs_encode`, `ReedSolomon`, `decodeMessage` |
| RS unified strategy (per-session) | [`broadcast/rs/strategy.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/rs/strategy.go) | `layer.rs_strategy` |
| Abstract RS mesh (strategy-only; includes Go `TestNetwork` topologies 0–1 + 4-node ring) | [`sim/scenario_test.go`](https://github.com/ethp2p/ethp2p/blob/main/sim/scenario_test.go) | `sim.rs_mesh`, `zig build simtest` |
| Gossipsub sim publish bytes (same layout as Go `encodeGossipsubMessage`) + default topic | [`sim/strategy_gossipsub.go`](https://github.com/ethp2p/ethp2p/blob/main/sim/strategy_gossipsub.go) | `sim.gossipsub_transport` |
| Abstract topic fanout + per-peer inboxes (no protobuf RPC) | same driver `Publish` / subscribe mesh | `sim.gossipsub_protocol` |
| Encode + fanout helper | `GossipsubNode.Publish` + topic delivery | `sim.gossipsub_broadcast` |
| App payload envelope entry point (re-export) | `encodeGossipsubMessage` | `broadcast.gossip` |
| Gossipsim cross-checks (golden envelope, mesh fanout, `broadcast.gossip` vs transport) | — | `sim.gossipsub_interop` |
| **Not in scope yet** | libp2p gossipsub host, QUIC simnet wiring, gossipsub **protobuf** RPC (IHAVE/IWANT wire), RLNC | — (see **Pending work** below) |

## Pending work

What is **in tree today**: wire + layer RS strategy, `broadcast.*` (engine / RS channel / session / `gossip`), abstract RS mesh (2-, 4-, and 6-node cases), and the **gossipsim** stack (`gossipsub_transport`, `gossipsub_protocol`, `gossipsub_broadcast`, `gossipsub_interop`). All of that is covered by `zig build test` (fast CI).

What is **still open** (not exhaustive):

- **Broadcast parity with Go**: No full dedup groups, `Strategy.Verified()` / async verify, or multi-scheme (RLNC, etc.) like the reference `broadcast/` stack.
- **Real gossipsub / simnet**: No **[marcopolo/simnet](https://github.com/marcopolo/simnet)** or libp2p host; no QUIC timing. Abstract tests only.
- **Gossipsub protobuf RPC**: IHAVE/IWANT (and friends) as in `go-libp2p-pubsub` are not encoded/decoded in Zig.
- **Large-network RS stress**: Go runs `TestLargeNetwork_RS` / `TestScalability` on `main` only; Zig does not yet mirror those long or huge topologies in default CI (the 6-node abstract mesh is already heavy enough for a quick run).
- **RLNC and other EC schemes**: Out of tree until the reference grows them and we add Zig analogues.
- **Docs / ops**: Keep `UPSTREAM.md` and vendored `.proto` pins in sync with [ethp2p](https://github.com/ethp2p/ethp2p); align `minimum_zig_version` / CI `ZIG_VERSION`.

## Requirements

- Zig **0.15.0** or newer (tested with **0.15.1**).

## Build

```sh
zig build
zig build test      # includes wire, layer, and abstract RS mesh tests
zig build simtest   # same test binary as `test` (explicit name for mesh-focused runs)
```

Add as a dependency and import the module `zig_ethp2p` (see `build.zig`).

## Compatibility policy

- Vendored `.proto` files under `proto/` should match the reference tree; pin the upstream git revision in `UPSTREAM.md`.
- Golden bytes in tests are produced with the same layouts as the Go reference (`proto.Marshal`, `WriteSelector`, `WriteFrame`, raw payload reads). If wire output diverges, fix Zig unless upstream changed.

## License

This repository’s `LICENSE` file is the **GNU Lesser General Public License v3.0** text, copied **verbatim** from [ethp2p `main` — `LICENSE`](https://github.com/ethp2p/ethp2p/blob/main/LICENSE), so it matches the reference implementation’s license document byte-for-byte.
