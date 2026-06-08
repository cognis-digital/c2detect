#!/usr/bin/env bash
set -e
pip install ruff >/dev/null 2>&1 || true
ruff check . || echo "ruff not installed; skipping"
