# c2detect — Advanced usage

## CI gate (fail the build on findings)
```yaml
- run: pip install cognis-c2detect
- run: c2detect scan . --format sarif --out c2detect.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: c2detect.sarif }
```

## Pipe into a SIEM / webhook
```bash
c2detect scan . --format json | python integrations/webhook.py --url "$COGNIS_WEBHOOK_URL"
```

## Drive it from an AI agent (MCP)
```jsonc
// claude_desktop_config.json
{ "mcpServers": { "c2detect": { "command": "c2detect", "args": ["mcp"] } } }
```

## Run a language port instead of Python
```bash
node ports/javascript/index.js .     # Node
( cd ports/go && go run . .. )        # Go single binary
( cd ports/rust && cargo run -- .. )  # Rust
```

## Ports & services
Default service/forward ports: **8000** (HTTP API), **8080** (alt), **3000** (UI), **9090** (metrics).
