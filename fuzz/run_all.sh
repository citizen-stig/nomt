#!/usr/bin/env bash
# Runs every cargo-fuzz target in parallel for 3 hours, splitting the CPU cores between them.
# Linux only (io_uring). Keeps fuzzing past crashes; logs go to fuzz/logs/<target>.log.
set -euo pipefail
cd "$(dirname "$0")/.."

DURATION=10800
targets=$(cargo +nightly fuzz list)
workers=$(( $(nproc) / $(wc -l <<< "$targets") ))
workers=$(( workers > 0 ? workers : 1 ))

cargo +nightly fuzz build
mkdir -p fuzz/logs
stamp=$(mktemp)

for target in $targets; do
    cargo +nightly fuzz run "$target" -- \
        -max_total_time=$DURATION -fork=$workers -ignore_crashes=1 \
        > "fuzz/logs/$target.log" 2>&1 &
done
wait

crashed=0
for target in $targets; do
    new=$(find "fuzz/artifacts/$target" -type f -newer "$stamp" 2>/dev/null | wc -l)
    echo "$target: $new new artifact(s)"
    (( new == 0 )) || crashed=1
done
rm -f "$stamp"
exit $crashed
