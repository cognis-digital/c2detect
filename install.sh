#!/usr/bin/env sh
# Universal installer for c2detect. Prefers uv > pipx > pip; installs from the repo.
set -e
SRC="git+https://github.com/cognis-digital/c2detect.git"
echo "Installing c2detect ..."
if command -v uv >/dev/null 2>&1; then uv tool install "$SRC"
elif command -v pipx >/dev/null 2>&1; then pipx install "$SRC"
elif command -v python3 >/dev/null 2>&1; then python3 -m pip install --user "$SRC"
else echo "Need uv, pipx, or python3+pip"; exit 1; fi
echo "Done. Run: c2detect --help"
