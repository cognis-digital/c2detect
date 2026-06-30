# Demos

Five runnable, audience-specific scenarios in [`../demos/`](../demos/). Each one
loads a real bundled telemetry fixture (`demos/NN-*/observations.json`), runs the
actual `c2detect` engine **fully offline**, prints narrated output, and exits 0 —
so they double as smoke tests for the public API.

```bash
PYTHONUTF8=1 python demos/run_all.py            # all five, end to end
PYTHONUTF8=1 python demos/05_campaign_correlation.py   # or just one
```

> `PYTHONUTF8=1` only matters on a cp1252 console (Windows); the demos print a
> few non-ASCII characters in their narration.

## Audience map

| # | Scenario | Audience | What it shows | Real API used |
|---|----------|----------|---------------|---------------|
| 1 | `01_soc_triage.py` | **SOC / blue team** | Prioritize a 5-host JARM egress sweep — 2 C2 hosts pulled out, 3 benign CDNs cleared, ranked for escalation | `scan_observations`, `ScanResult.top` |
| 2 | `02_threat_intel_feeds.py` | **Threat intel** | Cross-reference observations against the real abuse.ch Feodo + SSLBL feeds, served from the bundled offline snapshot | `feeds.feodo_c2_ips`, `feeds.sslbl_ja3`, `feeds.enrich_observation` |
| 3 | `03_detection_rules.py` | **Detection engineers** | Generate Sigma + Suricata rules from the signature DB; verify deterministic, clash-free SIDs | `rules.to_sigma`, `rules.to_suricata`, `signatures` |
| 4 | `04_incident_response.py` | **Incident response / DFIR** | Attribute a single intrusion staging 4 frameworks (CS + Sliver + Havoc + AdaptixC2), with the indicators that fired | `scan_observations`, `Match.indicators` |
| 5 | `05_campaign_correlation.py` | **Threat hunters** | Cluster a week of telemetry into shared-infrastructure campaigns via union-find, with the pivot evidence inline | `correlate`, `PIVOT_WEIGHTS` |

## 1. SOC triage — *prioritize the sweep*
**Audience:** SOC analysts and blue teams.
An alert points at a handful of egress IPs. c2detect scores the
`12-threat-hunt-jarm-sweep` export against the signature DB, separates the two
real C2 hosts (Sliver at 100%, Cobalt Strike) from the three benign CDN/cloud
endpoints, and hands back a severity-then-confidence ranked escalation list.

## 2. Threat-intel feed enrichment — *known-bad, offline*
**Audience:** threat-intelligence analysts.
The signature DB catches *default* fingerprints; feeds catch hosts already
*reported* as malicious. This demo enriches `13-threat-intel-feeds` against the
abuse.ch Feodo Tracker (C2 IPs) and SSLBL (JA3) feeds, served entirely from the
bundled air-gap snapshot — flagging Dridex/Emotet C2 IPs and a TrickBot JA3 with
zero network access.

## 3. Detection-rule generation — *ship the intelligence*
**Audience:** detection engineers / content authors.
Turns the bundled DB into deployable Sigma (SIEM) and Suricata (IDS/IPS) rules,
then proves the Suricata SIDs are unique and sit in the private 9.2M band so
they won't clash with ET/Talos. The same fingerprints that triage telemetry now
live in your SIEM and IDS.

## 4. Incident response — *attribute every stage*
**Audience:** incident responders / DFIR.
One intrusion (`11-multi-framework-incident`) staged four C2 frameworks.
c2detect attributes each host to its framework and prints the exact indicators —
JA3, JARM, URIs, banner, cert quirk, beacon cadence — that fired, producing the
per-host table that drops into an incident timeline.

## 5. Campaign correlation — *map the estate*
**Audience:** threat hunters / intel teams.
A detection names a tool; correlation names the *estate*. This demo clusters
`14-campaign-correlation` into two shared-infrastructure campaigns with
union-find, reporting the heaviest pivots first (reused cert serial, JARM) and
leaving the one host with no shared pivot isolated. Every pivot is a value two
hosts literally share — no actor attribution, nothing invented.

---

Each demo prints clear, narrated output and exits 0, so they double as smoke
tests — `tests/` covers the same code paths under `pytest`, including
`tests/test_demos.py` which imports and runs every scenario.
