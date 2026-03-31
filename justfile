# Zig developer recipes (parity in spirit with ethp2p's justfile; this tree is Zig-only).
# Reference: https://github.com/ethp2p/ethp2p/blob/main/justfile
# Requires: https://github.com/casey/just

default:
    @just --list

# Build the library (installs to zig-out by default).
build:
    zig build

# Full test suite (local default; CI uses split jobs — see .github/workflows/ci.yml).
test:
    zig build test --summary all

# CI splits (ethp2p workflow parity); each uses Debug + TSan (≈ go -race).
test-broadcast:
    zig build test-broadcast --summary all

test-sim-rs:
    zig build test-sim-rs --summary all

test-sim-gossipsub:
    zig build test-sim-gossipsub --summary all

# Optional QUIC + OpenSSL (Linux/macOS); same as CI job `quic-transport`.
test-quic:
    zig build test-quic -Denable-quic --summary all

# Main-branch CI job: full root + ZIG_ETHP2P_STRESS + TSan.
test-stress-ci:
    zig build test-stress-ci --summary all

# Same binary as `test`; name matches RS mesh / simnet-parity wording.
simtest:
    zig build simtest --summary all

# Longer RS mesh paths (sets ZIG_ETHP2P_STRESS=1).
test-stress:
    zig build test-stress --summary all

fmt:
    zig fmt .

fmt-check:
    zig fmt --check .

# Same assertion as CI: parse ZIG_VERSION from the workflow file and compare to build.zig.zon.
check-zig-ci-align:
    #!/usr/bin/env bash
    set -euo pipefail
    want="$(sed -n 's/^[[:space:]]*ZIG_VERSION: \([^[:space:]]*\).*/\1/p' .github/workflows/ci.yml | head -1)"
    test -n "$want" || { echo "could not parse ZIG_VERSION from .github/workflows/ci.yml"; exit 1; }
    got="$(sed -n 's/^[[:space:]]*\.minimum_zig_version = "\([^"]*\)".*/\1/p' build.zig.zon | head -1)"
    test -n "$got" || { echo "could not parse build.zig.zon"; exit 1; }
    test "$got" = "$want" || { echo "build.zig.zon minimum_zig_version=$got, ci.yml ZIG_VERSION=$want"; exit 1; }
    echo "OK: minimum_zig_version=$got"

# Local Zig caches and install prefix only.
clean:
    rm -rf .zig-cache zig-out
