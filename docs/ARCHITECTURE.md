# C2DETECT — Architecture

> C2 server fingerprinter — Cobalt Strike, Sliver, Mythic, Havoc, Brute Ratel

## Pipeline

```
input ──▶ collectors ──▶ analyzers/rules ──▶ scorer ──▶ findings ──▶ reporters
                                   │                          │
                              (this repo)               table · json · sarif · html
```

1. **Collectors** normalize the target (file, dir, API, or stream) into records.
2. **Analyzers / rules** apply the detection logic shipped in this repo's package.
3. **Scorer** (shared `cognis-core`) assigns severity and an aggregate risk score.
4. **Reporters** render findings to table / JSON / SARIF / HTML.
5. **MCP server** (`c2detect mcp`) exposes `scan` as a tool for Cognis.Studio agents.

## Shared framework

All Suite tools depend on **`cognis-core`** for the `Finding`, `ScanResult`, and
`score()` primitives, so findings are uniform across the portfolio and compose in
Cognis.Studio. Keeping per-tool logic thin and the core shared is what lets the
suite stay coherent across 52 tools.

## Extending

Detections/rules live in the package next to `core.py`. Add a rule, add a test in
`tests/`, and add (or extend) a `demos/NN-*/SCENARIO.md` so the behavior is covered
by the smoke-test corpus. See [CONTRIBUTING.md](../CONTRIBUTING.md).
