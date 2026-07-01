"""Scenario 16 - layered detection: signatures AND live feeds together.

**Audience:** SOC / threat-intel teams who want both signals on one host.

Signatures catch a *default* fingerprint; feeds catch a host already *reported*
malicious. The strongest verdict is when both fire — or when one covers the
other's blind spot. This demo runs the bundled feed snapshot (abuse.ch Feodo +
SSLBL, fully offline) AND the signature scanner over the same observations and
shows, per host, which layer caught it. Pure stdlib, zero network.
"""
import os

from _common import FEEDS_SNAPSHOT, load_observations, rule

os.environ.setdefault("COGNIS_FEEDS_CACHE", FEEDS_SNAPSHOT)

from c2detect import feeds                              # noqa: E402
from c2detect.core import observation_from_record, scan_observation  # noqa: E402


def main() -> None:
    rule("LAYERED DETECTION  -  signatures AND live feeds on each host")

    records = load_observations("13-threat-intel-feeds/observations.json")
    observations = [observation_from_record(r) for r in records]
    feodo = feeds.feodo_c2_ips(offline=True)
    ja3bl = feeds.sslbl_ja3(offline=True)

    print(f"\nInput: {len(records)} observations   "
          f"(feeds: {len(feodo)} C2 IPs, {len(ja3bl)} bad JA3s, offline)\n")

    print(f"  {'host':<18} {'signature layer':<26} feed layer")
    print("  " + "-" * 64)
    sig_only = feed_only = both = 0
    for obs in observations:
        host = obs.host or "(unnamed)"
        res = scan_observation(obs, threshold=35)
        sig = res.top.family if res.top else "-"
        hits = feeds.enrich_observation(obs, feodo=feodo, ja3bl=ja3bl)
        feed = ", ".join(h["source"] for h in hits) if hits else "-"
        if res.top and hits:
            both += 1
        elif res.top:
            sig_only += 1
        elif hits:
            feed_only += 1
        print(f"  {host:<18} {sig:<26} {feed}")

    print(f"\n  caught by signatures only : {sig_only}")
    print(f"  caught by feeds only       : {feed_only}")
    print(f"  caught by both layers      : {both}")
    print("\nA host whose TLS profile was customised away from any default is "
          "still flagged by the feed layer — and vice versa. Two independent "
          "signals, one offline scan.")


if __name__ == "__main__":
    main()
