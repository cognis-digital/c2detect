# Ports of c2detect

The c2detect **core check** — scoring a TLS/network *observation* (JARM / JA3 /
default port / staging URI) against a bundled subset of the C2-framework
signature DB — ported across languages so you can drop the detector into any
stack or ship a single static binary. Every port is **passive** (reads
files/JSON, never touches the network), uses the same family names and the same
weighted scoring (JARM 42, JA3 24, URI 16, port 6; report threshold 35), and
emits a `{"tool":"c2detect", ... ,"match_count":N}` JSON summary.

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | `../c2detect/` | `c2detect scan .` | `python -m pytest -q` |
| Go | `go/` | `cd ports/go && go run . obs.json` | `go test ./...` |
| Rust | `rust/` | `cd ports/rust && cargo run -- obs.json` | `cargo test` |
| JavaScript / Node | `javascript/` | `node ports/javascript/index.js obs.json` | `node test.js` |
| TypeScript | `typescript/` | `node --experimental-strip-types index.ts obs.json` | `node --experimental-strip-types --test index.test.ts` |
| Shell (POSIX) | `shell/` | `sh ports/shell/c2detect.sh obs.json` | `sh test.sh` |

Each port has its own minimal test suite. They are built and tested on GitHub
runners by `.github/workflows/ports.yml` (Go and Rust toolchains are not assumed
locally — CI is the source of truth for those).

> The ports implement the deterministic core only. The full reference engine
> (12+ families, behavioral beaconing, correlation, threat-intel feeds, SARIF,
> the authorized active probe) lives in the Python package.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
../CONTRIBUTING.md.
