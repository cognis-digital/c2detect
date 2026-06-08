#!/usr/bin/env bash
# Run every language port against the current dir.
set -e
node ports/javascript/index.js . 2>/dev/null || echo "node: skipped"
( cd ports/go && go run . .. ) 2>/dev/null || echo "go: skipped"
( cd ports/rust && cargo run -- .. ) 2>/dev/null || echo "rust: skipped"
