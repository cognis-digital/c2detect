# C2DETECT — C2 server fingerprinter — Cobalt Strike, Sliver, Mythic, Havoc, Brute Ratel

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `red-team`

[![PyPI](https://img.shields.io/pypi/v/cognis-c2detect.svg)](https://pypi.org/project/cognis-c2detect/)
[![CI](https://github.com/cognis-digital/c2detect/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/c2detect/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**C2 server fingerprinter — Cobalt Strike, Sliver, Mythic, Havoc, Brute Ratel.**

*Red Team / Offensive — adversary tooling for authorized engagements.*

## Why

Security and intelligence teams need c2 server fingerprinter — Cobalt Strike, Sliver, Mythic, Havoc, Brute Ratel without standing up heavyweight infrastructure. `c2detect` is single-purpose, scriptable, CI-friendly, and self-hostable: point it at a target, get prioritized findings in the format your workflow already speaks (table, JSON, SARIF, HTML), and wire it into agents over MCP when you want it autonomous.

## Install

```bash
pip install cognis-c2detect
# or, from this repo:
pip install -e ".[dev]"
```

## Quick start

```bash
c2detect --version
c2detect scan demos/                      # run against the bundled demo
c2detect scan demos/ --format sarif --out r.sarif --fail-on high
c2detect scan demos/ --format html --out report.html
c2detect mcp                              # expose as an MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Each scenario folder includes a `SCENARIO.md` describing the situation and the findings to expect.

- [`demos/01-cobalt-strike-network/`](demos/01-cobalt-strike-network/SCENARIO.md)
- [`demos/02-mixed-frameworks/`](demos/02-mixed-frameworks/SCENARIO.md)
- [`demos/03-benign-baseline/`](demos/03-benign-baseline/SCENARIO.md)

## Output formats

- **Table** (default) — human-readable terminal summary
- **JSON** — machine-readable findings for pipelines
- **SARIF** — drops into GitHub code-scanning / IDE problem panes
- **HTML** — shareable report with severity rollups

## Credits / Built on

Cognis composes and credits the best of open source. This tool builds on / interoperates with:

- [`salesforce/jarm`](https://github.com/salesforce/jarm) — TLS fingerprint
- [`FoxIO-LLC/ja4`](https://github.com/FoxIO-LLC/ja4) — JA4 fingerprints

Missing a credit? Open a PR — see [CONTRIBUTING.md](CONTRIBUTING.md).

## How it fits the Cognis Neural Suite

`c2detect` is one of **52 tools** in the [Cognis Neural Suite](https://github.com/cognis-digital). Every tool ships an MCP server, so [Cognis.Studio](https://cognis.studio) agents can call them as scoped capabilities.

**Sibling tools in `red-team`:** [`payloadlab`](https://github.com/cognis-digital/payloadlab), [`redpath`](https://github.com/cognis-digital/redpath), [`pwnreview`](https://github.com/cognis-digital/pwnreview), [`crackq`](https://github.com/cognis-digital/crackq)

## Architecture & roadmap

- Design notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Planned work: [`ROADMAP.md`](ROADMAP.md)

## Contributing

PRs, new detections, and demo scenarios are welcome under the collaboration-pull model. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

## Responsible use

This is dual-use security software. Use it only against systems, data, and identities you own or are explicitly authorized in writing to test, and in compliance with applicable law.

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
