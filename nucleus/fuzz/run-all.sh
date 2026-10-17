#!/bin/sh
# Runs every fuzz target for SECONDS each (default 120); crashes land in artifacts/<target>/
set -u
cd "$(dirname "$0")"
SECONDS_EACH="${1:-120}"
for target in handlers parsers packets link_messages report_and_import; do
    echo "=== $target"
    mkdir -p "corpus/$target"
    RUSTC_BOOTSTRAP=1 cargo fuzz run -s none "$target" "corpus/$target" "seeds/$target" -- \
        -max_total_time="$SECONDS_EACH" -rss_limit_mb=4096 -timeout=10 -print_final_stats=1 2>&1 \
        | grep -E "^#[0-9]+ +DONE|^stat::number_of_executed_units|^stat::peak_rss|cov:|panicked|ERROR|SUMMARY|Test unit written|deadly signal|Timeout|slowest" | tail -8
done
