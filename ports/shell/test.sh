#!/bin/sh
# Minimal test harness for the shell port. Run: sh test.sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SCAN="$DIR/c2detect.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fail=0

CS_JARM="07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"

# 1) Cobalt Strike JARM -> a match (rc 1) and match_count >= 1
printf '{"host":"x","jarm":"%s"}\n' "$CS_JARM" > "$TMP/cs.json"
out=$(sh "$SCAN" "$TMP/cs.json" || true)
echo "$out" | grep -q '"match_count":1' || { echo "FAIL: CS not matched: $out"; fail=1; }
echo "ok - cobalt strike jarm detected"

# 2) Clean file -> no match (match_count 0)
printf '{"host":"benign","port":443}\n' > "$TMP/clean.json"
out=$(sh "$SCAN" "$TMP/clean.json" || true)
echo "$out" | grep -q '"match_count":0' || { echo "FAIL: clean tripped: $out"; fail=1; }
echo "ok - clean file no match"

# 3) Metasploit URI -> match
printf 'GET /INITM HTTP/1.1\n' > "$TMP/msf.txt"
out=$(sh "$SCAN" "$TMP/msf.txt" || true)
echo "$out" | grep -q '"match_count":1' || { echo "FAIL: MSF not matched: $out"; fail=1; }
echo "ok - metasploit uri detected"

if [ "$fail" -eq 0 ]; then
  echo "\n3 passed"
else
  echo "\nTESTS FAILED"; exit 1
fi
