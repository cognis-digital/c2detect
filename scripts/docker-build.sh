#!/usr/bin/env bash
set -e
TOOL="$(basename "$PWD")"
docker build -t "cognis/$TOOL:local" .
echo "built cognis/$TOOL:local"
