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
| `DedupCancel` + `DedupGroup` token (session hook) | session → strategy `takeChunk` | `layer.broadcast_types`, `layer.dedup` |
| Engine-wide dedup registry (`channel` + `message` + chunk index) | multi-peer ingest dedup | `layer.dedup_registry`, `Engine.enable_cross_session_dedup` |
| Verify result FIFO (single-threaded `Verified()` shim) | async verify channels | `layer.verify_queue` |
| Verify worker pool (SHA256 vs preamble hash → queue) | background verify workers | `layer.verify_workers` |
| Relay session attach + `relayIngestChunk` / `relayIngestChunkVerified` | relay ingest path | `broadcast.channel_rs` |
| Async SHA256 verify → `relayIngestChunk` (driver polls `drainCompleted`) | Go `Verified()` → `handleVerifyResult` | `broadcast.relay_async_verify`, `layer.verify_workers` |
| RS routing bitmap | [`broadcast/rs/bitmap.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/rs/bitmap.go) | `layer.bitmap` |
| RS `Config` / `initPreamble` | [`broadcast/rs/types.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/rs/types.go) | `layer.rs_init` |
| RS emit planner (fair dispatch heap) | [`broadcast/rs/emit.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/rs/emit.go) | `layer.emit_planner` |
| RS parity encode (klauspost-default matrix) | [klauspost/reedsolomon](https://github.com/klauspost/reedsolomon) via ethp2p RS strategy | `layer.rs_encode`, `ReedSolomon`, `decodeMessage` |
| RS unified strategy (per-session) | [`broadcast/rs/strategy.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/rs/strategy.go) | `layer.rs_strategy` |
| Abstract RS mesh (strategy-only; Go `TestNetwork` 0–1, 4-node ring, eight-node ring under stress) | [`sim/scenario_test.go`](https://github.com/ethp2p/ethp2p/blob/main/sim/scenario_test.go) | `sim.rs_mesh`, `zig build simtest` |
| Gossipsub sim publish bytes (same layout as Go `encodeGossipsubMessage`) + default topic | [`sim/strategy_gossipsub.go`](https://github.com/ethp2p/ethp2p/blob/main/sim/strategy_gossipsub.go) | `sim.gossipsub_transport` |
| Abstract topic fanout + per-peer inboxes (no protobuf RPC) | same driver `Publish` / subscribe mesh | `sim.gossipsub_protocol` |
| Encode + fanout helper | `GossipsubNode.Publish` + topic delivery | `sim.gossipsub_broadcast` |
| App payload envelope entry point (re-export) | `encodeGossipsubMessage` | `broadcast.gossip` |
| Gossipsim cross-checks (golden envelope, mesh fanout, `broadcast.gossip` vs transport) | — | `sim.gossipsub_interop` |
| Gossipsub `ControlIHave` / `ControlIWant` protobuf bodies (subset of [libp2p `rpc.proto`](https://github.com/libp2p/go-libp2p-pubsub/blob/master/pb/rpc.proto)) | `ControlMessage` nested fields | `sim.gossipsub_rpc_pb`, `proto/gossipsub_rpc.proto` |
| Gossipsub top-level `RPC` with `control` only (field 3) | length-delimited `RPC` shell for stream payloads | `sim.gossipsub_rpc_pb` (`encodeRpcEnvelopeControl`, `decodeRpcControlOnly`) |
| **Still open** (see [issues](#pending-work)) | Full gossipsub `RPC`, libp2p/simnet host, RLNC, larger RS mesh graphs, optional channel-style event loop / `VerdictPending` for non-RS schemes | — |

## Pending work

**On `main` today:** wire + layer RS strategy; `layer.dedup` / `layer.dedup_registry` / `layer.verify_queue` / `layer.verify_workers`; `broadcast.*` (engine, channel, `relay_async_verify`, verified + unverified relay ingest); abstract RS mesh (2-, 4-, 6-node; optional **stress** adds six-node budget and **eight-node ring**); gossipsim stack; gossipsub `ControlIHave` / `ControlIWant` plus **`RPC` control-only envelope** helpers in `sim.gossipsub_rpc_pb`. CI enforces `build.zig.zon` `minimum_zig_version` vs workflow `ZIG_VERSION`; `just check-zig-ci-align` matches locally. Default `zig build test` stays fast.

**Suggested next:** [#13](https://github.com/ch4r10t33r/zig-ethp2p/issues/13) — extend `sim/rs_mesh.zig` with larger topologies and budgets aligned with Go `sim/scenario_test.go` (builds on existing mesh tests without new transport).

**Tracked issues** (roadmap, not exhaustive):

| Issue | Status / topic |
|-------|----------------|
| [#11](https://github.com/ch4r10t33r/zig-ethp2p/issues/11) | Open — dedup + verify pool + ingest; async `RelayAsyncVerifier` on `main`; engine-bound helpers (`*Engine` ingest, decode clears dedup) may land via open PR — close or narrow when merged |
| [#12](https://github.com/ch4r10t33r/zig-ethp2p/issues/12) | Open — full gossipsub `RPC`, libp2p streams, simnet/QUIC-style host |
| [#13](https://github.com/ch4r10t33r/zig-ethp2p/issues/13) | Open — RS abstract mesh: larger graphs & Go scalability alignment (**next up**) |
| [#14](https://github.com/ch4r10t33r/zig-ethp2p/issues/14) | Open — RLNC and additional EC `Scheme` types |
| [#15](https://github.com/ch4r10t33r/zig-ethp2p/issues/15) | **Closed** — `UPSTREAM.md` Zig toolchain note, CI `minimum_zig_version` check, `just check-zig-ci-align` |

## Requirements

- Zig **0.15.0** or newer (tested with **0.15.1**).

## Build

```sh
zig build
zig build test         # wire, layer, broadcast, sim (default CI)
zig build simtest      # alias of `test` (mesh-focused name)
zig build test-stress  # same tests with `ZIG_ETHP2P_STRESS=1` (longer RS mesh case)
```

Add as a dependency and import the module `zig_ethp2p` (see `build.zig`).

Optional: install [just](https://github.com/casey/just) and run `just` from the repo root for the same commands (`just build`, `just test`, `just fmt-check`, …); see [`justfile`](justfile) (similar role to [ethp2p’s `justfile`](https://github.com/ethp2p/ethp2p/blob/main/justfile)).

## Compatibility policy

- Vendored `.proto` files under `proto/` should match the reference tree; pin the upstream git revision in `UPSTREAM.md`.
- Golden bytes in tests are produced with the same layouts as the Go reference (`proto.Marshal`, `WriteSelector`, `WriteFrame`, raw payload reads). If wire output diverges, fix Zig unless upstream changed.

## License

This repository’s `LICENSE` file is the **GNU Lesser General Public License v3.0** text, copied **verbatim** from [ethp2p `main` — `LICENSE`](https://github.com/ethp2p/ethp2p/blob/main/LICENSE), so it matches the reference implementation’s license document byte-for-byte.
