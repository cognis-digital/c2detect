#!/bin/sh
# POSIX-shell port of the c2detect CORE check. Passive only; no network.
# Greps observation files for documented default C2 fingerprints and prints a
# JSON summary. Dependency-free (sh + grep). Same family names as the reference.
#
# Usage: c2detect.sh <file-or-dir>
set -eu

CS_JARM="07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"
CS_JA3="a0e9f5d64349fb13191bc781f81f42e1"
SLIVER_PORT="31337"
MSF_URI="/INITM"

scan_one() {
  # $1 = file. Echoes one single-token family id per high-confidence signal.
  f=$1
  if grep -qi "$CS_JARM" "$f" 2>/dev/null || grep -qi "$CS_JA3" "$f" 2>/dev/null; then
    echo "cobalt_strike"
  fi
  if grep -q "$SLIVER_PORT" "$f" 2>/dev/null && grep -q "/staticfile" "$f" 2>/dev/null; then
    echo "sliver"
  fi
  if grep -q "$MSF_URI" "$f" 2>/dev/null; then
    echo "metasploit"
  fi
}

main() {
  target=${1:-.}
  count=0
  families=""
  if [ -d "$target" ]; then
    files=$(find "$target" -type f 2>/dev/null)
  else
    files=$target
  fi
  for f in $files; do
    [ -f "$f" ] || continue
    for fam in $(scan_one "$f"); do
      count=$((count + 1))
      families="$families $fam"
    done
  done
  printf '{"tool":"c2detect","match_count":%d,"score":%d}\n' "$count" "$count"
  [ "$count" -eq 0 ] && return 0 || return 1
}

main "$@"
