#!/usr/bin/env bash
set -e
V="$(cat VERSION 2>/dev/null || echo 0.1.0)"
git tag -a "v$V" -m "release v$V" && echo "tagged v$V (push with: git push --tags)"
