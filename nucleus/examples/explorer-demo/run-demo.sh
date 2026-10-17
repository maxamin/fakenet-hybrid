#!/bin/sh
# The explorer, end to end, on a real (harmless) binary: bot.c is built with function-level
# coverage, REA's Ghidra analysis supplies its functions & strings, and the bot talks to the
# nucleus (localhost, high ports, no daemon, no diversion) twice: with the explorer off,
# then on. Prints which of the bot's functions each run reached.
#
# Usage: examples/explorer-demo/run-demo.sh [REA_JSON...]
#   Without REA files, it runs scripts/rea-hints.sh (REA + Ghidra) on the exact binary it
#   builds: the analysis must be of the same build, or coverage maps to the wrong functions.
#   ROUNDS=150 and KEEP=1 (keep the work folder) are optional.
set -eu
cd "$(dirname "$0")/../.."
NUCLEUS="$(pwd)/target/debug/fakenet-nucleus"
WORK="$(mktemp -d)"
ROUNDS="${ROUNDS:-150}"
trap '[ -n "${KEEP:-}" ] && echo "kept $WORK" || rm -rf "$WORK"' EXIT
gcc -O0 -no-pie -fno-pie -finstrument-functions -o "$WORK/bot" examples/explorer-demo/bot.c
if [ $# -eq 0 ]; then
    echo "Analysing the bot with REA (Ghidra; a few minutes)..."
    scripts/rea-hints.sh "$WORK/bot" "$WORK/rea.jsonl" ghidra > "$WORK/rea.log" 2>&1 || { cat "$WORK/rea.log"; exit 1; }
    set -- "$WORK/rea.jsonl"
fi
REA_LIST=""
for f in "$@"; do REA_LIST="$REA_LIST\"$(cd "$(dirname "$f")" && pwd)/$(basename "$f")\", "; done

run() { # name explorer-enabled
    mkdir -p "$WORK/$1/coverage"
    cat > "$WORK/$1/fakenet.toml" <<CONFIG
[nucleus]
bind = "127.0.0.1"
capture_dir = "capture"
health = "127.0.0.1:47099"
[daemon]
websocket_url = ""
http_url = ""
[explorer]
enabled = $2
rate = 0.85
seed = 7
samples = ["$WORK/bot"]
rea = [$REA_LIST]
coverage_dir = "coverage"
[[listener]]
name = "HTTP"
protocol = "http"
port = 47080
[[listener]]
name = "DNS"
protocol = "dns"
transport = "udp"
port = 47053
[[listener]]
name = "Auto"
protocol = "auto"
port = 47337
CONFIG
    "$NUCLEUS" -c "$WORK/$1/fakenet.toml" > "$WORK/$1/nucleus.log" 2>&1 &
    pid=$!
    for _ in $(seq 50); do curl -sf http://127.0.0.1:47099/health >/dev/null 2>&1 && break; sleep 0.2; done
    COVERAGE_FILE="$WORK/$1/coverage/bot.jsonl" "$WORK/bot" 127.0.0.1 47080 47053 47337 "$ROUNDS"
    sleep 2 # The coverage watcher polls every second
    kill -INT "$pid"; wait "$pid" || true
    # Functions the bot entered, by name (non-PIE: runtime addresses are the binary's)
    grep -o '0x[0-9a-f]*' "$WORK/$1/coverage/bot.jsonl" | sort -u | while read -r address; do
        nm "$WORK/bot" | awk -v a="$(printf '%016x' "$address")" '$1 == a && ($3 ~ /^cmd_|^fallback/) {print $3}'
    done | sort -u > "$WORK/$1/reached.txt"
    echo "$1: $(wc -l < "$WORK/$1/reached.txt") command handlers reached: $(tr '\n' ' ' < "$WORK/$1/reached.txt")"
}
run defaults false
run explorer true
MAP="$WORK/explorer/capture/explorer-map.json"
echo
python3 - "$MAP" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
print(f"explorer map: {m['proposals']} answers, {m['behaviors']} kinds of behaviour, functions reached {len(m['functions']['reached'])} of {m['functions']['known']} known (from REA)")
for t in m["templates"][:8]:
    if t["reward"] > 0:
        fns = [f for f in t["functions"] if f.startswith(("cmd_", "fallback"))]
        print(f"  {t['template']:<24} reward {t['reward']:>7} -> {', '.join(fns) or '(behaviour only)'}")
print("  best tokens:", ", ".join(x["token"] for x in m["tokens"][:8]))
PY
