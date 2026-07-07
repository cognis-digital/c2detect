# Demos

Twenty runnable, audience-specific scenarios in [`../demos/`](../demos/). Each one
runs the actual `c2detect` engine **fully offline** against bundled telemetry
fixtures (or synthesized observations built from documented defaults), prints
narrated output, and exits 0 — so they double as smoke tests for the public API.

```bash
PYTHONUTF8=1 python demos/run_all.py            # all twenty, end to end
PYTHONUTF8=1 python demos/12_correlation_graph.py   # or just one
```

> `PYTHONUTF8=1` only matters on a cp1252 console (Windows); the demos print a
> few non-ASCII characters in their narration.

Every scenario is covered under `pytest` (`tests/test_demos.py` imports and runs
each `main()`), so the demos can never silently rot.

## Audience map

| # | Scenario | Audience | What it shows | Real API used |
|---|----------|----------|---------------|---------------|
| 1 | `01_soc_triage.py` | **SOC / blue team** | Prioritize a 5-host JARM egress sweep — 2 C2 pulled out, 3 benign CDNs cleared, ranked for escalation | `scan_observations`, `ScanResult.top` |
| 2 | `02_threat_intel_feeds.py` | **Threat intel** | Cross-reference against the real abuse.ch Feodo + SSLBL feeds from the bundled offline snapshot | `feeds.feodo_c2_ips`, `feeds.sslbl_ja3`, `feeds.enrich_observation` |
| 3 | `03_detection_rules.py` | **Detection engineers** | Generate Sigma + Suricata rules from the DB; verify deterministic, clash-free SIDs | `rules.to_sigma`, `rules.to_suricata`, `signatures` |
| 4 | `04_incident_response.py` | **IR / DFIR** | Attribute a 4-framework intrusion (CS + Sliver + Havoc + AdaptixC2) with the indicators that fired | `scan_observations`, `Match.indicators` |
| 5 | `05_campaign_correlation.py` | **Threat hunters** | Cluster a week of telemetry into shared-infrastructure campaigns via union-find | `correlate`, `PIVOT_WEIGHTS` |
| 6 | `06_sarif_code_scanning.py` | **AppSec / platform** | Emit SARIF 2.1.0 so C2 findings land as GitHub code-scanning alerts; verify the rule/result contract | `to_sarif` |
| 7 | `07_ci_gate.py` | **DevSecOps** | Exit codes that hard-fail a pipeline only on critical C2 (`--fail-on`) | `fails_gate`, `worst_severity` |
| 8 | `08_html_report.py` | **Reporting / MSSP** | Render a single self-contained HTML report (no external assets) for a stakeholder | `to_html`, `worst_severity` |
| 9 | `09_status_badge.py` | **Maintainers** | A shields.io endpoint badge whose colour reflects worst severity | `to_badge` |
| 10 | `10_jsonl_streaming.py` | **Data engineering** | Ingest Zeek/Suricata NDJSON straight in; auto-map sensor field names | `load_records`, `observation_from_record` |
| 11 | `11_freetext_telemetry.py` | **On-call analysts** | Scan an unstructured proxy/chat blob with no JSON | `observation_from_text`, `scan_text` |
| 12 | `12_correlation_graph.py` | **Intel viz** | Render the campaign pivot graph as Graphviz DOT for a brief | `correlate`, `to_dot` |
| 13 | `13_threshold_tuning.py` | **Detection tuning** | Sweep the confidence threshold to trade recall against false positives | `scan_observations` |
| 14 | `14_signature_inventory.py` | **Coverage review** | Audit every family, severity, and indicator class in the DB | `list_signatures` |
| 15 | `15_coverage_selfcheck.py` | **QA / release gate** | Run the bundled self-check: malicious fires, benign stays quiet | `selfcheck.run_self_check` |
| 16 | `16_feeds_plus_signatures.py` | **SOC / intel** | Run signatures AND offline feeds on each host; show which layer caught it | `feeds`, `scan_observation` |
| 17 | `17_beacon_cadence.py` | **Behavioral hunting** | Catch a beacon by its rhythm when every static IOC was rotated | `Observation`, `scan_observation` |
| 18 | `18_sigma_per_family.py` | **SIEM content** | Read a single generated Sigma rule end-to-end; prove its UUID is stable | `signatures`, `rules.sigma_rule` |
| 19 | `19_correlate_gate.py` | **Hunt automation** | Gate a pipeline on a correlated *campaign* severity, not a lone host | `correlate`, `SEVERITY_ORDER` |
| 20 | `20_air_gap_workflow.py` | **Air-gapped enclave** | The full offline pipeline (scan → feeds → correlate → SARIF) with the network forbidden | `feeds`, `correlate`, `to_sarif`, `datafeeds` |

## Scenario notes

**1–5** are the audience flagships (SOC, threat-intel, detection engineering, IR,
threat hunting) — see the inline docstrings for the full narrative.

**6 SARIF / code-scanning.** Renders a multi-framework incident as SARIF 2.1.0 and
verifies one rule per family, one result per match, and that every result
references a declared rule — so c2detect findings drop into the same UI as your
SAST/DAST alerts.

**7 CI gate.** Reproduces the exit-code contract (`0` clean / `1` finding /
`2` `--fail-on` hard-fail) across a benign baseline, Cobalt Strike, and Sliver,
so you can let low-severity heuristics through while breaking the build on a
critical hit.

**8 HTML report.** Generates a self-contained HTML file (no CDN, no fonts, no
remote assets) and checks it is valid and complete — safe to email, attach, or
open on an air-gapped box.

**9 status badge.** Produces the shields.io endpoint JSON for a clean baseline and
a live detection, ready to wire into a README badge.

**10 JSONL / NDJSON.** Parses a heterogeneous sensor stream (`dest_ip`,
`server_port`, `server_header`, `http_paths` …) with the real loader and field
aliaser — no reshaping.

**11 free-text triage.** Harvests fingerprints, ports and URIs from raw blobs
(explicit `key: value` pairs and free-floating tokens) and scans them.

**12 correlation graph.** Renders the campaign cluster as Graphviz DOT; pipe to
`dot -Tsvg` for a one-page infrastructure map.

**13 threshold tuning.** Sweeps the confidence floor across a mixed batch to show
how flagged counts move — pick the floor that fits your noise budget.

**14 signature inventory.** Walks the DB and prints a coverage table (family,
severity, indicator classes), highlighting which families are backed by a
decisive TLS fingerprint versus port/URI heuristics.

**15 self-check coverage.** Runs the release-gate self-check and asserts HEALTHY
(every malicious scenario fires, every benign baseline stays quiet).

**16 layered detection.** Runs the offline feed snapshot AND the signature scanner
over the same observations and tabulates which layer caught each host.

**17 beacon cadence.** Feeds (interval, jitter) pairs with no TLS fingerprint
through the behavioral heuristic and shows which trip it and which are dismissed
as too jittery or off-cadence.

**18 Sigma per family.** Prints one full generated Sigma rule and verifies its
structure and deterministic UUID, so a content author can review before shipping.

**19 campaign gate.** Gates a pipeline on the worst severity of any *clustered*
campaign — automation escalates an incident (shared infra across hosts), not the
noise.

**20 air-gap workflow.** Runs scan → offline feed enrichment → correlation →
SARIF export with the network hard-forbidden, proving the disconnected-enclave
story end to end.

---

Each demo prints clear, narrated output and exits 0, so they double as smoke
tests — `tests/` covers the same code paths under `pytest`.
