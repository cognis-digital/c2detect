#!/usr/bin/env bash
set -e
TOOL="$(basename "$PWD")"
"$TOOL" scan demos/ || python -m "$(basename "$PWD" | tr - _)" scan demos/ || true
