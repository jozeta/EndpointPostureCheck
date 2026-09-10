#!/bin/bash
# Concatenates src/*.zsh (filename order) into the shippable single-file artifact.
set -euo pipefail

SRC_DIR="${1:-src}"
OUT_FILE="${2:-Invoke-MacPostureCheck.sh}"

if [[ ! -d "$SRC_DIR" ]]; then
    echo "Source directory not found: $SRC_DIR" >&2
    exit 1
fi

{
    echo "#!/usr/bin/env zsh"
    echo "# EndpointPostureCheck for macOS — built $(date '+%Y-%m-%d %H:%M:%S') from src/*.zsh. Do not edit directly."
    for f in "$SRC_DIR"/*.zsh; do
        echo ""
        echo "# ---- $(basename "$f") ----"
        # Drop each module's own shebang line; only the top-level shebang above is kept.
        tail -n +2 "$f"
    done
} > "$OUT_FILE"

chmod +x "$OUT_FILE"
echo "Built $OUT_FILE from $(ls "$SRC_DIR"/*.zsh | wc -l | tr -d ' ') source file(s)."
