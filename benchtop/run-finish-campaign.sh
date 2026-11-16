#!/usr/bin/env bash
# One run of the `session.finish` campaign benchmark (benchtop/src/bin/finish_bench.rs).
# Restores the frozen seed database, then times `finish` over the run window.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR=/mnt/rollup/nomt-finish
unset RUSTFLAGS CARGO_PROFILE_RELEASE_LTO

cargo build --release --locked --quiet --manifest-path "$ROOT/benchtop/Cargo.toml" --bin finish_bench

rm -rf "$DIR/work-db"
cp -a --sparse=always "$DIR/seed-db" "$DIR/work-db"
sync

taskset -c 2-7,10-15 "$ROOT/benchtop/target/release/finish_bench" run "$DIR/work-db" "$DIR/seed-state"
