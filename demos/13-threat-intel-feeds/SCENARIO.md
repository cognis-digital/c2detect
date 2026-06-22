# Demo 13 — live threat-intel feed enrichment (edge / air-gap, fully offline)

C2DETECT's signature DB matches *default* C2 fingerprints. This demo adds the
second signal: cross-referencing each observation against real abuse.ch feeds
so a host already **known** to be malicious is flagged even with a customised
TLS profile.

This directory doubles as a pre-seeded **air-gap snapshot**: the four
`*.data` / `*.meta.json` files are a trimmed cache of the two feeds c2detect
consumes (`feodo-c2`, `sslbl` JA3). Point the cache at it and run `--offline`
— no network required, exactly as on a disconnected enclave.

```bash
# Serve the bundled snapshot as the feed cache (sneakernet-style).
export COGNIS_FEEDS_CACHE="$PWD/demos/13-threat-intel-feeds"

# Which feeds does c2detect consume?  (filtered to the threat-intel domain)
c2detect feeds list

# Enrich a batch of observations entirely offline.
c2detect scan demos/13-threat-intel-feeds/observations.json --feeds --offline
```

Expected: `45.142.212.61` flagged CRITICAL (Dridex C2 IP, Feodo Tracker) plus
its JA3 flagged HIGH (TrickBot, SSLBL); `185.220.101.45` flagged CRITICAL
(Emotet C2 IP); the `192.0.2.10` / bogus-JA3 row stays clean.

## Refreshing the snapshot on a connected host

```bash
c2detect feeds update                         # fetch feodo-c2 + sslbl JA3
python -m c2detect.datafeeds snapshot-export feeds.tar.gz   # sneakernet it
# …on the air-gapped side…
python -m c2detect.datafeeds snapshot-import feeds.tar.gz
c2detect scan obs.json --feeds --offline
```

Real sources (keyless, public):
- Feodo Tracker C2 IP blocklist — <https://feodotracker.abuse.ch/downloads/ipblocklist.json>
- SSLBL malicious JA3 fingerprints — <https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv>

Defensive / authorized-use intelligence only.
