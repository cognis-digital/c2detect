#!/usr/bin/env bash
# macOS setup via Homebrew.
set -euo pipefail
command -v brew >/dev/null 2>&1 || /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install python@3.12 git jq
python3 -m pip install --upgrade pip
[ -f pyproject.toml ] && python3 -m pip install -e ".[dev]" || true
echo "macOS setup complete."
