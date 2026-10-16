#!/usr/bin/env bash
# Bundles src/*.sh (in sorted order) into a single standalone dist/escal8.sh.
# Run from the repo root: ./build.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$ROOT_DIR/src"
DIST_DIR="$ROOT_DIR/dist"
OUT="$DIST_DIR/escal8.sh"

mkdir -p "$DIST_DIR"
: > "$OUT"

shopt -s nullglob
files=("$SRC_DIR"/*.sh)
shopt -u nullglob

if [ "${#files[@]}" -eq 0 ]; then
    echo "No source files found in $SRC_DIR" >&2
    exit 1
fi

# Sort numerically by filename prefix so e.g. 02_ comes before 10_.
IFS=$'\n' sorted=($(printf '%s\n' "${files[@]}" | sort))
unset IFS

# The kernel only honors a shebang ("#!...") if it is the literal first two
# bytes of the file - a blank line or comment before it silently turns
# `./escal8.sh` into a plain-text-executable fallback to /bin/sh instead of
# bash, which Escal8's own "requires bash" guard then (correctly, but
# confusingly) refuses. So the very first module's shebang line, if it has
# one, is written as line 1 of the output with nothing before it; the
# module-boundary comment for that file follows it instead of preceding it.
first=1
for f in "${sorted[@]}"; do
    base="$(basename "$f")"
    if [ "$first" -eq 1 ] && [ "$(head -c 2 "$f")" = "#!" ]; then
        head -n 1 "$f" >> "$OUT"
        {
            printf '# ============================== %s ==============================\n' "$base"
            tail -n +2 "$f"
        } >> "$OUT"
    else
        {
            printf '\n# ============================== %s ==============================\n' "$base"
            cat "$f"
        } >> "$OUT"
    fi
    first=0
done

chmod +x "$OUT"
echo "Built $OUT ($(wc -l < "$OUT") lines) from ${#sorted[@]} modules:"
for f in "${sorted[@]}"; do echo "  - $(basename "$f")"; done
