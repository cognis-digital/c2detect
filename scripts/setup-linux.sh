#!/usr/bin/env bash
# Cross-distro Linux setup (apt/dnf/pacman/apk/zypper).
set -euo pipefail
if   command -v apt-get >/dev/null; then sudo apt-get update -y && sudo apt-get install -y python3 python3-pip python3-venv git jq curl
elif command -v dnf     >/dev/null; then sudo dnf install -y python3 python3-pip git jq curl
elif command -v pacman  >/dev/null; then sudo pacman -Sy --noconfirm python python-pip git jq curl
elif command -v apk     >/dev/null; then sudo apk add python3 py3-pip git jq curl
elif command -v zypper  >/dev/null; then sudo zypper install -y python3 python3-pip git jq curl
fi
python3 -m pip install --upgrade pip
[ -f pyproject.toml ] && python3 -m pip install -e ".[dev]" || true
echo "Linux setup complete."
