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
   - `go-libp2p-pubsub/pb/rpc.proto` (for `proto/gossipsub_rpc.proto` field numbers; see `sim/gossipsub_rpc_pb.zig`)
2. Run `zig build test` (golden bytes must still match `google.golang.org/protobuf` output from that tree).
3. Bump the commit hash in this file.

## Abstract mesh tests

`src/sim/rs_mesh.zig` runs the same RS **settings and graph topologies** as `sim/scenario_test.go` (`TestNetwork` RS / RS-ChunkLen) against `layer.RsStrategy` in-process (no libp2p, no Go simnet). Adjacency and per-peer stats are **heap-allocated** (`MaxMeshNodes` cap). `zig build test` and `zig build simtest` both execute them. With `ZIG_ETHP2P_STRESS=1` (see `zig build test-stress`), extra cases use higher round budgets and add **8- and 16-node** ring graphs beyond the Go file’s largest fixed topology.

## Specifications

Normative docs: [ethp2p/specs](https://github.com/ethp2p/ethp2p/tree/main/specs) (architecture `001-ethp2p`, broadcast `002`–`004`).

## Wire compatibility

- **Length-prefixed frames** match `broadcast/wire.go` (`MaxFrameSize`, big-endian `uint32` length, then payload).
- **Stream opener** is a **single byte** (`protocol/protocol.go` `WriteSelector` / `ReadSelector`), equal to the `Protocol` enum value. The `Selector` protobuf in `protocol.proto` describes that enum for codegen; the reference does not length-prefix or protobuf-encode the selector on the wire.
- **CHUNK streams** (`broadcast/peer_ctrl.go` `doSendChunk`, `peer_in.go` `processChunk`): `0x03`, then length-framed `Chunk.Header`, then exactly `data_length` bytes of payload (not framed).
- **BCAST / SESS** high-level open helpers mirror `peer.go` / `peer_ctrl.go` / `peer_in.go` (see `wire/bcast_stream.zig`, `wire/sess_stream.zig`).
- **Protobuf field numbers** for framed messages match the `.proto` definitions; tests include hex from the Go reference.
