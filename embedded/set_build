#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "${1:-}" in
  pico|sender|s)
    cat > "$here/.build_target" <<EOF
BUILD_TARGET=pico
OUT_DIR=pico
EOF
    echo "Selected: Pico. Wrote $here/.build_target"
    ;;
  pi4|receiver|r)
    cat > "$here/.build_target" <<EOF
BUILD_TARGET=pi4
OUT_DIR=pi4
EOF
    echo "Selected: Pi 4. Wrote $here/.build_target"
    ;;
  status)
    [[ -f "$here/.build_target" ]] && cat "$here/.build_target" || echo "No .build_target set."
    ;;
  *)
    echo "Usage: $0 {pico|pi4|status}" >&2
    exit 1
    ;;
esac
