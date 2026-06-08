#!/usr/bin/env bash
set -e
TOOL="$(basename "$PWD")"
time "$TOOL" scan . >/dev/null
