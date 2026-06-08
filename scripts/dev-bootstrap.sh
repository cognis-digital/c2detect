#!/usr/bin/env bash
# Create a venv, install dev deps, run tests + a smoke scan.
set -euo pipefail
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
pytest -q || true
TOOL="$(basename "$PWD")"
"$TOOL" --version || true
echo "Dev environment ready in .venv/"
