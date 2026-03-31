# Zig developer recipes (parity in spirit with ethp2p's justfile; this tree is Zig-only).
# Reference: https://github.com/ethp2p/ethp2p/blob/main/justfile
# Requires: https://github.com/casey/just

default:
    @just --list

# Build the library (installs to zig-out by default).
build:
    zig build

# Full test suite (same as CI).
test:
    zig build test --summary all

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

# Local Zig caches and install prefix only.
clean:
    rm -rf .zig-cache zig-out
