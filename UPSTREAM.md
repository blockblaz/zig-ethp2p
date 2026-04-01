# Upstream alignment

This repository tracks **[ethp2p](https://github.com/ethp2p/ethp2p)**.

## Zig toolchain

`build.zig.zon` `minimum_zig_version` must match the `ZIG_VERSION` environment variable in [`.github/workflows/ci.yml`](.github/workflows/ci.yml). CI fails the job if they differ, so bump both when raising the supported Zig release.

## Pinned revision

The vendored `.proto` files and golden test vectors were checked against reference commit:

`125bdaa3985a8cbe9f24d53155828312777b73fc`

As of the last maintenance pass, **ethp2p** `main` still points at this commit, so `proto/*.proto` matched `broadcast/pb/`, `protocol/pb/`, and `broadcast/rs/pb/` in that tree without edits.

When updating:

1. Diff `proto/*.proto` against:
   - `broadcast/pb/broadcast.proto`
   - `protocol/pb/protocol.proto`
   - `broadcast/rs/pb/rs.proto`
   - `go-libp2p-pubsub/pb/rpc.proto` (for `proto/gossipsub_rpc.proto` field numbers; `sim/gossipsub_rpc_pb.zig` implements `RPC` 1–3 and **10** (`partial` / `PartialMessagesExtension`), full `ControlMessage`, varint length-prefixed framing; other extension field numbers are skipped on decode. `sim/gossipsub_rpc_host.zig` is an in-process duplex for framed `RPC`, not a libp2p transport.)
2. Run `zig build test` (golden bytes must still match `google.golang.org/protobuf` output from that tree).
3. Bump the commit hash in this file.

## QUIC / UDP transport

`src/transport/eth_ec_quic.zig` mirrors **ALPN** `eth-ec-broadcast` and high-level **quic-go-style** limits from ethp2p `sim/host.go`. With `-Denable-quic` it links [`gitlab.com/devnw/zig/quic`](https://gitlab.com/devnw/zig/quic) (pinned in `build.zig.zon`) and OpenSSL on non-Windows; use `zig build test-quic -Denable-quic` for the focused QUIC test binary (see `src/ci_root_quic.zig`).

### macOS: integration tests skipped (handshake mutex abort)

On **Darwin**, the loopback TLS+QUIC integration tests in `eth_ec_quic_enabled.zig` and `eth_ec_quic_wire_enabled.zig` are **skipped** (`error.SkipZigTest`) because they reliably crash the process (often reported as **signal 9** when not under a debugger).

**Observed under lldb (Zig 0.15.1, devnw/quic 0.1.10, Homebrew OpenSSL 3):** the failure is **`EXC_BREAKPOINT`** in `libsystem_platform` `_os_unfair_lock_corruption_abort` while locking `std.Thread.Mutex` on a QUIC `Connection`. The stack is **`endpoint/incoming/module_b.zig`** `processHandshake` → `conn.*.mu.lock()` → `Thread.Mutex.DarwinImpl.lock`, after `endpoint.poll` processes an incoming datagram. It reproduces in **Debug** and **ReleaseSafe** builds of the test binary. **Linux** does not show this; CI should keep running `test-quic` there.

**Not** fixed by: TLS SNI matching the embedded cert CN (`ed25519.example.com`), early `OPENSSL_init_ssl`, `quic.poll` ordering (client vs server first), `page_allocator` instead of `GeneralPurposeAllocator`, or raising test stack size. Treat as a **devnw/quic (or Zig stdlib Mutex interaction) issue on macOS** until upstream confirms otherwise.

**When re-enabling:** remove the `builtin.os.tag == .macos` skip guards in those two tests and run `zig build test-quic -Denable-quic` on a Mac. Until then, `EthEcQuicConfig.tls_server_name` remains the right knob when dialing loopback to a cert issued for a DNS name (SNI must match the certificate).

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
