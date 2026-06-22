# Campaign correlation — clustering C2 infrastructure across hosts

> **Scope.** Defensive / authorized-triage / situational-awareness only.
> C2DETECT *reads* observations and *clusters* them. It performs no network
> calls, no scanning, no active capability, and does **not** attribute clusters
> to any named threat actor. It surfaces evidence; a human analyst adjudicates.

`c2detect correlate` is the cross-host analysis mode. A single detection tells
you "this host looks like Cobalt Strike." Correlation tells you the thing that
actually drives an incident response: **which of your hosts belong to the same
operator's infrastructure**, and *why* — with the exact shared indicators that
joined them.

```
c2detect scan      ->  per-host verdict   ("host X resembles family Y")
c2detect correlate ->  estate-level map   ("hosts X, Z, W are one campaign;
                                            here are the 3 pivots that link them")
```

---

## The threat model, frankly

Mature adversaries treat the cheap parts of their infrastructure as disposable
and rotate them aggressively: domains, IPs, and URL paths churn between
intrusions, sometimes between days. Detecting a single beacon and blocking one
IP is whack-a-mole — the operator re-points the implant and you are blind again.

What adversaries rotate *slowly* — because it is operationally expensive — is
the **shape** of their listener and certificate stack:

| Pivot | Why it leaks across hosts | Forge cost |
|-------|---------------------------|-----------|
| **Reused x509 serial** | A cert minted once and copied across redirectors carries the same serial number. | Near-conclusive — serials are not coincidental. |
| **JA4X cert fingerprint** | Derived from the cert's structure; default-profile certs are identical. | Very high. |
| **JARM** | A fingerprint of how the *server* answers TLS handshakes — a function of the TLS library + listener config. One C2 build → one JARM across the whole redirector farm. | High; requires re-architecting the listener. |
| **JA4S / JA3S** | Server-hello fingerprints; same idea, different generation. | High. |
| **Shared cert CN / issuer** | Self-signed defaults reuse the same subject string. | Moderate. |
| **Same family + severity** | Two CS beacons are weak alone, but corroborate other pivots. | Low (corroborating only). |
| **Identical URI path / beacon cadence** | A shared malleable profile across the estate. | Low–moderate. |
| **Shared port** | Almost meaningless — 443 is shared by the whole internet. | ~Zero. |

Correlation exploits exactly this asymmetry: it links hosts on the **expensive-
to-rotate** indicators and ignores the cheap, noisy ones. Two IPs you have
never associated, sharing one JARM, are very likely the same kit and config.
Two sharing a **cert serial** are, for practical triage purposes, the same
infrastructure.

> This is the same logic FoxIO's JARM/JA4+ databases, Censys/Shodan "same
> certificate" pivots, and JA3 hunting all rely on — applied locally, offline,
> to *your own* telemetry, with the evidence shown inline.

---

## How the engine works

1. **Score** every observation with the normal detection engine (so each host
   carries a top family + severity).
2. **Extract pivot features** per host — the bucketed set of values for each
   pivot class (JARM, JA4S, cert serial, cert CN, family, URI, beacon, …).
   Beacon intervals are bucketed to the nearest 5 s so near-identical sleeps
   fuse; cert serials and CNs are parsed out of the cert text blob.
3. **Draw edges.** For every pair of hosts, compute the indicators they
   *literally share*. The edge's joint weight is the **sum of distinct pivot-
   class weights** (one shared JARM counts once, but a shared JARM *and* a
   shared cert serial reinforce). An edge is kept only if its weight clears the
   `--edge-floor` (default **24**) — so a lone shared port (weight 4) never
   fuses two hosts, but a shared JARM (40) always does.
4. **Cluster** with union-find: connected components over the edge graph become
   campaigns. Linking is transitive — if A–B and B–C are both linked, A, B, C
   are one campaign even if A and C share nothing directly.
5. **Score & rank.** Campaign confidence = strongest single edge + a breadth
   bonus for more members and more distinct strong pivot classes, capped at 100.
   Severity is the worst of any member's. Campaigns sort strongest-first.

Pivot weights live in `c2detect.correlate.PIVOT_WEIGHTS` and are deliberately
distinct from single-host `core.WEIGHTS`: here the question is "how unlikely is
this match *across two independent hosts*," not "how diagnostic is it on one."

---

## Worked walkthrough

You pulled a week of TLS/HTTP telemetry from your egress sensor and dumped it as
observation records. Six hosts tripped some level of suspicion. Are they
related?

```bash
$ c2detect correlate week_telemetry.json
== Campaign #0  [CRITICAL]  confidence=100  hosts=3  families: Cobalt Strike
   host: 203.0.113.10
   host: 203.0.113.11
   host: 203.0.113.12
   shared infrastructure pivots:
     - cert_serial (w=50): 0a1b2c3d4e5f6a7b
     - jarm (w=40): 07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
     - family (w=18): cobalt strike
     - port (w=4): 443

== Campaign #1  [HIGH]  confidence=58  hosts=2  families: Metasploit / Meterpreter
   host: 198.51.100.5
   host: 198.51.100.6
   shared infrastructure pivots:
     - jarm (w=40): 07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d

c2detect: 2 campaign(s) clustering 5 host(s) by shared C2 infrastructure.
```

The read:

* **Campaign #0** — three hosts on *different ports*, two with different cert
  CNs, all sharing **one cert serial** and **one JARM**. That is one Cobalt
  Strike team-server's redirector farm. Block the serial/JARM at your TLS
  inspection point, not just the IPs — the operator can re-IP in minutes but
  re-minting and re-deploying a cert across the estate is slower.
* **Campaign #1** — two Metasploit listeners sharing a JARM. Lower confidence
  (single pivot class, two hosts) but still a clear pair.
* The sixth host (a benign `nginx` on :80) shared nothing above the floor and
  was **not** clustered — exactly what you want.

### CI gate

```bash
# Fail the pipeline if any campaign reaches CRITICAL severity.
c2detect correlate week_telemetry.json --fail-on critical   # exit 2
```

### Visualize the pivot graph

`--format dot` emits Graphviz. Edge thickness scales with pivot strength and the
label names the top pivot class:

```bash
c2detect correlate week_telemetry.json --format dot | dot -Tsvg -o campaigns.svg
```

### Tuning

```bash
# Strict: require a strong server fingerprint (JARM-class) to link hosts.
c2detect correlate obs.json --edge-floor 38

# Inventory mode: also list lone, unclustered hosts.
c2detect correlate obs.json --include-singletons

# Only report high-confidence campaigns.
c2detect correlate obs.json --campaign-threshold 60
```

### Programmatic / MCP

```python
from c2detect import correlate_observations, Observation
camps = correlate_observations([Observation(host="a", jarm=JARM),
                                Observation(host="b", jarm=JARM)])
print(camps[0].confidence, camps[0].hosts)
```

The MCP server (`c2detect mcp`) exposes a `correlate` tool alongside `scan` and
`list_signatures`, so an agent can pivot from "is this host C2?" to "what else
shares its infrastructure?" in one call.

---

## What it deliberately does **not** do

* It does **not** name threat actors. A shared JARM means "same kit/config,"
  not "APT-N." Attribution is an analyst judgment on top of this evidence.
* It invents nothing. Every reported pivot is a value two observations
  *literally* share. There are no fabricated serials, hashes, or fingerprints.
* It takes no network action. No scanning, no probing, no blocking — output is
  an analysis document.

---

## Diagram

![C2DETECT correlation pivot graph](correlation_graph.svg)

*Figure: three redirectors sharing one JARM + cert serial cluster into a single
campaign (red); two Metasploit listeners cluster on a shared JARM (orange); the
benign host stays isolated. Generated SVG, CC0 / public-domain — Cognis Digital.*
