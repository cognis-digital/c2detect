"""Scenario 2 - threat intel: enrich observations with live abuse.ch feeds.

**Audience:** threat-intelligence analysts.

The signature DB catches *default* C2 fingerprints. But a host that has already
been reported as an active botnet C2 is worth flagging even when its TLS profile
has been customised away from any documented default. This demo cross-references
each observation against the real abuse.ch Feodo Tracker (C2 IPs) and SSLBL
(malicious JA3) feeds — served entirely from the bundled air-gap snapshot, so it
runs with zero network access, exactly as on a disconnected enclave.
"""
import os

from _common import FEEDS_SNAPSHOT, load_observations, rule

# Point the feeds cache at the bundled snapshot BEFORE importing the feed layer
# so it re-serves the trimmed cache offline (no network, like an air-gapped box).
os.environ.setdefault("COGNIS_FEEDS_CACHE", FEEDS_SNAPSHOT)

from c2detect import feeds                       # noqa: E402
from c2detect.core import observation_from_record  # noqa: E402


def main() -> None:
    rule("THREAT INTEL  -  abuse.ch feed enrichment, fully offline")

    records = load_observations("13-threat-intel-feeds/observations.json")
    observations = [observation_from_record(r) for r in records]
    print(f"\nInput: {len(records)} observations "
          "(demos/13-threat-intel-feeds)")
    print(f"Feeds cache: {FEEDS_SNAPSHOT}  (offline snapshot)\n")

    feodo = feeds.feodo_c2_ips(offline=True)
    ja3bl = feeds.sslbl_ja3(offline=True)
    print(f"Loaded {len(feodo)} Feodo C2 IP(s) and {len(ja3bl)} SSLBL JA3(s) "
          "from cache.\n")

    total_hits = 0
    for rec, obs in zip(records, observations):
        host = obs.host or "(unnamed)"
        hits = feeds.enrich_observation(obs, feodo=feodo, ja3bl=ja3bl)
        if not hits:
            print(f"  [CLEAN   ] {host:<18} no feed match")
            continue
        for h in hits:
            total_hits += 1
            extra = h.get("malware") or h.get("reason") or ""
            print(f"  [{h['severity'].upper():<8}] {host:<18} "
                  f"{h['source']} → {extra}")
            print(f"             {h['title']}")

    print(f"\n{total_hits} live-intel hit(s). A known-bad host is flagged even "
          "when its fingerprint was customised away from a default.")
    print("Every byte came from the cached snapshot — nothing left the box.")


if __name__ == "__main__":
    main()
