# zig-ethp2p

Zig helpers for the wire formats of **[ethp2p](https://github.com/ethp2p/ethp2p)** — the reference implementation is **[github.com/ethp2p/ethp2p](https://github.com/ethp2p/ethp2p)** ([specs directory](https://github.com/ethp2p/ethp2p/tree/main/specs)). This repo tracks that code and the protobuf definitions under `broadcast/pb`, `protocol/pb`, and `broadcast/rs/pb`. Optional **QUIC** transport (TLS 1.3, ALPN `eth-ec-broadcast`, unidirectional streams) builds on **lsquic + BoringSSL** when you pass **`-Denable-quic`**; see [QUIC transport](#quic-transport-optional-lsquic-build).

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
| Relay session attach + `relayIngestChunk` / `relayIngestChunkVerified` / `relayIngestChunk*Engine` | relay ingest path | `broadcast.channel_rs` |
| Async SHA256 verify → `relayIngestChunk` (driver polls `drainCompleted`); `initBound` uses engine dedup | Go `Verified()` → `handleVerifyResult` | `broadcast.relay_async_verify`, `layer.verify_workers` |
| Decode clears cross-session dedup keys | registry lifecycle after reconstruction | `sessionDecodeClearEngineDedup` |
| RS routing bitmap | [`broadcast/rs/bitmap.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/rs/bitmap.go) | `layer.bitmap` |
| RS `Config` / `initPreamble` | [`broadcast/rs/types.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/rs/types.go) | `layer.rs_init` |
| RS emit planner (fair dispatch heap) | [`broadcast/rs/emit.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/rs/emit.go) | `layer.emit_planner` |
| RS parity encode (klauspost-default matrix) | [klauspost/reedsolomon](https://github.com/klauspost/reedsolomon) via ethp2p RS strategy | `layer.rs_encode`, `ReedSolomon`, `decodeMessage` |
| RS unified strategy (per-session) | [`broadcast/rs/strategy.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/rs/strategy.go) | `layer.rs_strategy` |
| EC scheme id (per-channel `Scheme` name; RS only wired) | [`broadcast/types.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/types.go) `Scheme`, [`broadcast/rs/types.go`](https://github.com/ethp2p/ethp2p/blob/main/broadcast/rs/types.go) `NewScheme` (`"reed-solomon"`) | `layer.ec_scheme` (`EcSchemeKind`); RLNC / more schemes → [#14](https://github.com/ch4r10t33r/zig-ethp2p/issues/14) |
| Abstract RS mesh (heap-backed adjacency + `PeerSessionStats`; cap `MaxMeshNodes`; Go `TestNetwork` 0–1, 4-node ring; **partition/heal** for CI's `TestNodeReconnection` filter — no matching Go test on ethp2p `main` today; 8- / 16-node rings under stress) | [`sim/scenario_test.go`](https://github.com/ethp2p/ethp2p/blob/main/sim/scenario_test.go), [`.github/workflows/ci.yml`](https://github.com/ethp2p/ethp2p/blob/main/.github/workflows/ci.yml) `simnet-rs` | `sim.rs_mesh` (`MeshParams.partition`), `zig build simtest` |
| Gossipsub sim publish bytes (same layout as Go `encodeGossipsubMessage`) + default topic | [`sim/strategy_gossipsub.go`](https://github.com/ethp2p/ethp2p/blob/main/sim/strategy_gossipsub.go) | `sim.gossipsub_transport` |
| Abstract topic fanout + per-peer inboxes (no protobuf RPC) | same driver `Publish` / subscribe mesh | `sim.gossipsub_protocol` |
| Encode + fanout helper | `GossipsubNode.Publish` + topic delivery | `sim.gossipsub_broadcast` |
| App payload envelope entry point (re-export) | `encodeGossipsubMessage` | `broadcast.gossip` |
| Gossipsim cross-checks (golden envelope, mesh fanout, `broadcast.gossip` vs transport) | — | `sim.gossipsub_interop` |
| Gossipsub `ControlIHave` / `ControlIWant` / `ControlGraft` / `ControlPrune` / `ControlIDontWant`, full `ControlMessage` | [libp2p `rpc.proto`](https://github.com/libp2p/go-libp2p-pubsub/blob/master/pb/rpc.proto) | `sim.gossipsub_rpc_pb`, `proto/gossipsub_rpc.proto` |
| Gossipsub top-level `RPC` (`subscriptions`, `publish`, `control`, `partial`) + control-only envelope | stream payloads; unknown RPC field numbers still skipped except **10** (`partial`) | `sim.gossipsub_rpc_pb` (`encodeRpc` / `decodeRpcOwned`, `encodeRpcEnvelopeControl`, `decodeRpcControlOnly`) |
| `PartialMessagesExtension` (nested in `RPC.partial`) | libp2p `rpc.proto` field 10 body | `encodePartialMessagesExtension`, `decodePartialMessagesExtensionOwned` |
| Unsigned-varint length prefix before `RPC` body | common libp2p framing | `encodeRpcLengthPrefixed`, `decodeRpcLengthPrefixedPrefix` |
| In-process duplex for length-prefixed `RPC` (simnet-style, no TCP/QUIC) | pair of `Endpoint`s over bounded byte queues | `sim.gossipsub_rpc_host` (`Link`, `Endpoint.sendRpc` / `recvRpcOwned`) |
| QUIC transport + UNI stream alignment | [`sim/host.go`](https://github.com/ethp2p/ethp2p/blob/main/sim/host.go), `peer.go`, `peer_ctrl.go`, `peer_in.go` | `transport.eth_ec_quic`: IETF QUIC, TLS 1.3, ALPN `eth-ec-broadcast`, **unidirectional** BCAST/SESS/CHUNK streams matching `OpenUniStream`/`AcceptUniStream`; `PeerConn` lifecycle sketch. See [QUIC transport](#quic-transport-optional-lsquic-build). |
| **Still open** | — | [Pending work](#pending-work) |

## Scope on `main` (at a glance)

This is **what is already implemented** — not the backlog. Per-module mapping and upstream links are in the [implementation table](#implementation-status-vs-reference).

- **Wire and RS:** length-prefixed frames, stream selector, BCAST / SESS / CHUNK streams, RS `Preamble` / `ChunkIdent` framing (`wire.*`, `layer.rs_init`, `layer.rs_encode`, `layer.rs_strategy`, `layer.bitmap`, `layer.emit_planner`).
- **Dedup and verify:** `layer.dedup`, `layer.dedup_registry`, `layer.verify_queue`, `layer.verify_workers`; relay / async-verify paths in `broadcast.channel_rs` and `broadcast.relay_async_verify`.
- **Broadcast stack:** `broadcast.engine`, `broadcast.session_rs`, `broadcast.observer`, and related session hooks aligned with ethp2p's broadcast layer.
- **EC scheme id:** `layer.ec_scheme` (`EcSchemeKind`, `"reed-solomon"` wire name); only Reed–Solomon is wired end-to-end ([#14](https://github.com/ch4r10t33r/zig-ethp2p/issues/14) tracks RLNC and further schemes).
- **Abstract RS mesh:** heap-backed graphs and `PeerSessionStats` (`sim.rs_mesh`): 2-node, 4-node ring, 6-node `TestNetwork`-style topology, **partition/heal** line test, chunk-len variant; with `ZIG_ETHP2P_STRESS=1`, larger six-node budget plus **8-** and **16-node** rings.
- **Gossipsub (sim / wire helpers):** transport, protocol, broadcast, interop, `RPC` encode/decode (including **`partial`** / `PartialMessagesExtension`), full `ControlMessage`, varint length prefix, in-process **`gossipsub_rpc_host`** for tests (`sim.gossipsub_*`, `broadcast.gossip`).
- **QUIC (optional):** `transport.eth_ec_quic` — IETF QUIC, TLS 1.3, ALPN `eth-ec-broadcast`, **unidirectional** BCAST/SESS/CHUNK streams matching the ethp2p Go reference (`peer.go` `OpenUniStream`/`AcceptUniStream`). `PeerConn` poll-driven lifecycle sketch included. See [QUIC transport](#quic-transport-optional-lsquic-build).
- **CI:** aligned with [ethp2p's `ci.yml`](https://github.com/ethp2p/ethp2p/blob/main/.github/workflows/ci.yml): `zig build test-broadcast`, `test-sim-rs`, `test-sim-gossipsub` (Debug + TSan), `test-quic -Denable-quic` (**`quic-transport`** job: vendored TLS, **45m** job timeout + **`timeout 40m`** on the command so a hung poll loop cannot exhaust the runner), `test-stress-ci` on **`main` only**, plus lint (`zig fmt --check`, `zig build`, `zig ast-check`). `build.zig.zon` **`minimum_zig_version`** must match workflow **`ZIG_VERSION`**; `just check-zig-ci-align` checks that locally.
- **One-shot local verification:** `zig build test` runs the full suite.

## QUIC transport (optional lsquic build)

Enable the full stack with **`-Denable-quic`** on the `zig build` command line (see [Build](#build)).

**Layout**

| Piece | Role |
|-------|------|
| `build.zig` | `-Denable-quic` pulls **`lsquic_zig`** (LiteSpeed **lsquic** + **BoringSSL**), exposes Zig module `quic` rooted at `src/transport/lsquic_quic_shim.zig`, links **zlib** (+ **pthread** / **m** on Unix). **Windows** is rejected for this flag (upstream build focus). |
| `lsquic_quic_shim.zig` | Endpoint/connection/stream API: UDP I/O, `poll`, `connect`, `tryAccept`, `handshakeComplete`, `streamMake` (bidi), `streamMakeUni` (UNI), `tryAcceptIncomingUniStream`, stream read/write/cancel helpers. |
| `eth_ec_quic_common.zig` / `eth_ec_quic_enabled.zig` | Shared config and ALPN string; **enabled** path implements `listenImpl` / `dialImpl` and integration tests. |
| `eth_ec_quic.zig` | Public `transport.eth_ec_quic`: `listen`, `dial`, `logInit` (programmatic lsquic logger), listener wrapper. |
| `eth_ec_quic_peer.zig` | `PeerConn` poll-driven state machine: `idle → handshaking → active → closed`; symmetric BCAST UNI handshake + `runAcceptLoop` dispatch by protocol selector byte. |
| `vendor/lsquic_zig/patch_uni.sh` | Build-time patch that removes `static` from `create_uni_stream_out` in lsquic and appends a public `lsquic_conn_make_uni_stream()` wrapper (lsquic 4.3 has no public API for outgoing UNI streams). |

**Operation**

Callers must **drive the engine**: after I/O, use **`quic.poll(endpoint, timeout_ms)`**. For `timeout_ms == 0` (tight loops), the shim advances wall clock using **`lsquic_engine_earliest_adv_tick`** (capped micro-sleep) so PTO-style timers can fire.

**Unidirectional streams**

All ethp2p application protocols use UNI streams — both peers independently open their own send stream (`peer.go` `OpenUniStream`), avoiding simultaneous-open ambiguity inherent in bidirectional streams for P2P protocols. See `UPSTREAM.md` for the full rationale.

**TLS notes**

- **Ed25519 server certs:** BoringSSL's default TLS 1.3 client handshake may omit Ed25519; the client **`SSL_CTX`** sets **`SSL_CTX_set_verify_algorithm_prefs`** so Ed25519 certificates work (otherwise TLS alert 40).
- **SNI:** Clients should pass a hostname that matches the server certificate (see `eth_ec_quic_test_certs.zig` for embedded test identity).

**Debugging**

Call **`quic.logInit("debug")`** (or any `lsquic_set_log_level` level) to enable lsquic's stderr logger programmatically.  Alternatively, set the env var **`ZIG_ETHP2P_LSQUIC_LOG=1`** (or **`LSQUIC_LOG_LEVEL`**) before the first `listen`/`dial`; the shim picks that up on first use.

## Pending work

- **`PeerConn` wiring:** connect `eth_ec_quic_peer.zig` to `Engine`/channel tables (currently a lifecycle sketch only).
- **Erasure coding:** **RLNC** (strategy, preamble, chunk layout) and any further `Scheme` types beyond Reed–Solomon ([#14](https://github.com/ch4r10t33r/zig-ethp2p/issues/14)).
- **libp2p:** Noise handshake, multistream-select, Yamux, identify — handled by zeam's rust-libp2p layer; out of scope for this repo.

## Requirements

- Zig **0.15.1** or newer.

## Build

```sh
zig build
zig build test              # full suite (wire, layer, broadcast, sim)
zig build simtest           # alias of `test` (mesh-focused name)
zig build test-stress       # `ZIG_ETHP2P_STRESS=1` (longer RS mesh + 8-/16-node ring cases)
zig build test-broadcast    # CI split: wire + layer + broadcast (TSan)
zig build test-sim-rs       # CI split: RS mesh (TSan)
zig build test-sim-gossipsub
zig build test-quic -Denable-quic   # lsquic + BoringSSL handshake / transport tests; CI `quic-transport`
zig build test-stress-ci    # full suite + stress + TSan (same as `large-network-rs` on main)
```

Add as a dependency and import the module `zig_ethp2p` (see `build.zig`).

Optional: install [just](https://github.com/casey/just) and run `just` from the repo root for the same commands (`just build`, `just test`, `just fmt-check`, …); see [`justfile`](justfile) (similar role to [ethp2p's `justfile`](https://github.com/ethp2p/ethp2p/blob/main/justfile)).

## Compatibility policy

- Vendored `.proto` files under `proto/` should match the reference tree; pin the upstream git revision in `UPSTREAM.md`.
- Golden bytes in tests are produced with the same layouts as the Go reference (`proto.Marshal`, `WriteSelector`, `WriteFrame`, raw payload reads). If wire output diverges, fix Zig unless upstream changed.

## License

This repository's `LICENSE` file is the **GNU Lesser General Public License v3.0** text, copied **verbatim** from [ethp2p `main` — `LICENSE`](https://github.com/ethp2p/ethp2p/blob/main/LICENSE), so it matches the reference implementation's license document byte-for-byte.
