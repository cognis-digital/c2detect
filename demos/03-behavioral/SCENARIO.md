# Behavioral demo — beacon cadence, URI patterns, and the AI mode

This scenario exercises C2DETECT's **behavioral** heuristics — the indicators
that survive when an operator rotates their TLS profile and certificates. All
data is synthetic lab telemetry; every value is a documented public default.

## What it shows

`observations.json` carries four hosts:

1. **198.51.100.91** — a textbook implant: a **60s fixed-cadence beacon** with
   ~5% jitter, a 4-char **checksum-style stager URI** (`/aB3x`, matched by the
   Cobalt Strike `uri_regex`), and the Cobalt Strike **default User-Agent**.
   None of these is a TLS fingerprint — they're purely behavioral/observational.
2. **203.0.113.55** — MITRE **Caldera** Sandcat default endpoints (`/beacon`,
   `/file/download`).
3. **192.0.2.77** — an **hourly** low-jitter call-home. No family-specific
   indicator, but the *cadence shape* alone trips the **Generic Beaconing
   Heuristic** (low severity, behavioral-only).
4. **10.0.0.8** — a 60s interval but **90% jitter**. High jitter is *not* a
   default-Beacon shape, so the strict Cobalt Strike profile is **not** tripped
   — demonstrating that the jitter ceiling actually gates.

## Run it

```sh
# Behavioral detection (exit 1 == C2 indicators found).
# Host 1 fires at the default threshold on its stacked behavioral indicators.
python -m c2detect scan demos/03-behavioral/observations.json

# Surface the weaker single-indicator leads (Caldera URI, hourly beacon shape):
python -m c2detect scan demos/03-behavioral/observations.json --threshold 15

# Self-contained HTML report
python -m c2detect scan demos/03-behavioral/observations.json --format html > report.html

# shields.io status badge endpoint JSON
python -m c2detect scan demos/03-behavioral/observations.json --format badge

# OPT-IN AI pass (off by default; needs a local Cognis fleet endpoint).
# With no backend — or an unreachable one — it prints a note and falls back
# to the deterministic rule findings, never crashing:
python -m c2detect scan demos/03-behavioral/observations.json --ai
```

## What to expect

Host 1 attributes to **Cobalt Strike** at the default threshold (uri_regex +
user_agent + beacon cadence + port stack up). Hosts 2–3 are weaker single-
indicator leads that surface with `--threshold 15` (Caldera URIs; the Generic
Beaconing Heuristic on the hourly low-jitter shape). Host 4 stays clean against
the strict CS jitter ceiling at any threshold. The exit code is non-zero so it
gates CI. Adding `--ai` (with a configured local fleet) layers in LLM-suggested
*novel* candidates, deduped against the rule findings and tagged `source="ai"`.
