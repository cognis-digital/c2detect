#!/usr/bin/env bash
# Minimal prerequisites only (no project install). Ubuntu/Debian.
set -euo pipefail
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo apt-get install -y --no-install-recommends python3 python3-pip python3-venv git curl jq
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y python3 python3-pip git curl jq
elif command -v brew >/dev/null 2>&1; then
  brew install python git jq
fi
python3 --version && git --version
