#!/usr/bin/env bash
# Cognis Neural Suite — Ubuntu/Debian setup. Installs prerequisites + this tool.
set -euo pipefail
echo "==> Cognis setup (Ubuntu/Debian)"
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  sudo apt-get update -y
  sudo apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv build-essential \
    git curl wget jq ca-certificates
fi
python3 -m pip install --upgrade pip
# editable install with dev extras when a pyproject is present
if [ -f pyproject.toml ]; then
  python3 -m pip install -e ".[dev]" || python3 -m pip install -e .
fi
echo "==> done. Try: $(basename "$PWD") --version"
