#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/dist/sarif-writer/sarif-writer.h}
mkdir -p "$(dirname "$out")"

{
    cat "$root/include/sarif-writer/sarif-writer.h"
    echo
    echo "#if defined(SARW_IMPLEMENTATION) && !defined(SARW_IMPLEMENTATION_DONE)"
    echo "#define SARW_IMPLEMENTATION_DONE"
    for src in "$root"/src/*.h "$root"/src/*.c; do
        [ -f "$src" ] && grep -v '^#include "' "$src"
    done
    echo "#endif"
} > "$out"
echo "$out"
