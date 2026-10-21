#!/bin/bash
# Runs every fuzz target for SECONDS each (default 120); crashes land in artifacts/<target>/
# Exits non-zero if any target failed (a crash, a timeout or a build error).
set -u -o pipefail
cd "$(dirname "$0")"
SECONDS_EACH="${1:-120}"
failed=()
for target in handlers parsers packets link_messages report_and_import model; do
    echo "=== $target"
    mkdir -p "corpus/$target"
    RUSTC_BOOTSTRAP=1 cargo fuzz run -s none "$target" "corpus/$target" "seeds/$target" -- \
        -max_total_time="$SECONDS_EACH" -rss_limit_mb=4096 -timeout=10 -print_final_stats=1 2>&1 \
        | { grep -E "^#[0-9]+ +DONE|^stat::number_of_executed_units|^stat::peak_rss|cov:|panicked|ERROR|SUMMARY|Test unit written|deadly signal|Timeout|slowest" || true; } | tail -8
    status=${PIPESTATUS[0]}
    if [ "$status" -ne 0 ]; then
        echo "!!! $target failed (exit $status); see artifacts/$target/"
        failed+=("$target")
    fi
done
if [ "${#failed[@]}" -gt 0 ]; then
    echo "Failed targets: ${failed[*]}"
    exit 1
fi
