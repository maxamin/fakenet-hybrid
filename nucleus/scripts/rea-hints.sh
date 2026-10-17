#!/bin/sh
# Analyzes a sample with REA (Reverse Engineer Anything, https://github.com/morluto/rea)
# and saves its Evidence (JSON lines) for the explorer: set [explorer] rea = ["<output>"] and
# samples = ["<sample>"]. The explorer imports every procedure ({address, name}) and string
# record it finds, wherever REA's Evidence nests them: function names become coverage
# targets & command words, strings become hints.
#
# Usage: scripts/rea-hints.sh SAMPLE OUTPUT.json [PROVIDER]
#   PROVIDER: ghidra (default), ida, hopper, kuna... (REA's own provider setup applies:
#   e.g. a local Ghidra). Uses an installed `rea`, else `npx -y rea-agents@6.5.0`.
# Run it in the analysis environment: REA analyzes statically, it doesn't run the sample.
set -eu
[ $# -ge 2 ] || { echo "Usage: $0 SAMPLE OUTPUT.json [PROVIDER]" >&2; exit 2; }
SAMPLE="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
OUTPUT="$2"
PROVIDER="${3:-ghidra}"
if command -v rea >/dev/null; then REA=rea; else REA="npx -y rea-agents@6.5.0"; fi

# Every procedure and every string (REA's search, with a match-all regex), plus the
# overview (image base), as JSON lines: one Evidence record per line
{
    $REA search "$SAMPLE" --pattern='.*' --mode regex --kind procedures --provider "$PROVIDER" --format jsonl
    $REA search "$SAMPLE" --pattern='.*' --mode regex --kind strings --provider "$PROVIDER" --format jsonl
    $REA analyze "$SAMPLE" --provider "$PROVIDER" --format jsonl
} > "$OUTPUT"
echo "Wrote $OUTPUT (use it as [explorer] rea = [\"$OUTPUT\"]; image_base: see its binary_overview record)"
