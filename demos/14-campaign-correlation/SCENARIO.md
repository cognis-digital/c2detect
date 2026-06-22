# Campaign correlation: who shares infrastructure?

**Expected output:** two campaigns + one isolated benign host.

A week of egress TLS telemetry gave you six suspicious-ish hosts. Scanning them
one at a time tells you *what* each looks like — but not whether they belong
together. `c2detect correlate` clusters hosts that share **expensive-to-rotate**
C2 infrastructure (reused cert serial, shared JARM) into campaigns, so you can
respond to the *estate* instead of playing IP whack-a-mole.

## Run it

```bash
c2detect correlate demos/14-campaign-correlation/observations.json
c2detect correlate demos/14-campaign-correlation/observations.json --format json
c2detect correlate demos/14-campaign-correlation/observations.json --format dot | dot -Tsvg -o campaigns.svg
```

## What you should see

* **Campaign #0 (CRITICAL)** — `45.77.65.211`, `45.77.65.212`, `104.21.5.7`.
  Three hosts on different ports, two with different cert CNs, all sharing one
  **cert serial** and one **JARM** = one Cobalt Strike team-server's redirector
  farm. Block the serial/JARM, not just the IPs.
* **Campaign #1** — `198.51.100.5`, `198.51.100.6`. Two Metasploit listeners
  sharing a JARM (lower confidence: a single strong pivot class across two
  hosts).
* `142.250.80.46` (benign CDN) shares nothing above the edge floor and is **not**
  clustered.

```bash
# Gate a pipeline on any CRITICAL campaign (exit 2):
c2detect correlate demos/14-campaign-correlation/observations.json --fail-on critical
```

All indicators here are public documented defaults or clearly-synthetic example
values. c2detect does not attribute to a named actor and invents nothing — every
shared pivot is a value two observations literally share. Defensive
situational-awareness only; no network action. See
[docs/CORRELATION.md](../../docs/CORRELATION.md).
