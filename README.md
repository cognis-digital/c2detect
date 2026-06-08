# C2DETECT — C2 server fingerprinter — Cobalt Strike, Sliver, Mythic, Havoc, Brute Ratel

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> MIT License · domain: `red-team`

[![PyPI](https://img.shields.io/pypi/v/cognis-c2detect.svg)](https://pypi.org/project/cognis-c2detect/)
[![CI](https://github.com/cognis-digital/c2detect/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/c2detect/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

C2 server fingerprinter — Cobalt Strike, Sliver, Mythic, Havoc, Brute Ratel.

## Install

```bash
pip install cognis-c2detect
```

For local development from this repo:

```bash
pip install -e .
```

## Quick start

```bash
c2detect --version
c2detect scan demos/                          # run against bundled demo
c2detect scan demos/ --format sarif --out r.sarif --fail-on high
c2detect mcp                                   # start as MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Every scenario folder includes a `SCENARIO.md` describing what it represents and what findings to expect.

- `demos/01-cobalt-strike-network/` — see [`SCENARIO.md`](demos/01-cobalt-strike-network/SCENARIO.md)
- `demos/02-mixed-frameworks/` — see [`SCENARIO.md`](demos/02-mixed-frameworks/SCENARIO.md)
- `demos/03-benign-baseline/` — see [`SCENARIO.md`](demos/03-benign-baseline/SCENARIO.md)

## How it fits the Cognis Neural Suite

This tool is one of 52 in the [Cognis Neural Suite](https://github.com/cognis-digital). The full suite + launcher lives at:

- Suite landing: https://cognis.digital
- All 52 repos: https://github.com/cognis-digital
- Cognis.Studio (Enterprise AI Workforce, MCP host): https://cognis.studio

Every Suite tool ships an MCP server, so Cognis.Studio agents can call them as scoped capabilities.

## License

MIT. See [LICENSE](LICENSE).

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
