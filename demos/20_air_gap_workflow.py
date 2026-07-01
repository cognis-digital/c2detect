"""Scenario 20 - air-gapped enclave: the full offline triage workflow.

**Audience:** operators on a disconnected / classified network.

c2detect is built to run with zero network: the signature DB is bundled, and the
threat-intel feeds are sneakernetted in as a cached snapshot. This demo runs the
*whole* pipeline — signature scan, offline feed enrichment, campaign correlation,
and a SARIF export — against bundled fixtures with the network hard-forbidden, to
prove the air-gap story end to end. Every byte comes from disk.
"""
import os

from _common import FEEDS_SNAPSHOT, load_observations, rule

os.environ.setdefault("COGNIS_FEEDS_CACHE", FEEDS_SNAPSHOT)

from c2detect import feeds, datafeeds                   # noqa: E402
from c2detect.core import (                             # noqa: E402
    observation_from_record, scan_observation, scan_observations, to_sarif,
)
from c2detect.correlate import correlate                # noqa: E402


def main() -> None:
    rule("AIR-GAP WORKFLOW  -  full offline pipeline, network forbidden")

    # Hard-forbid the network for the entire run: any fetch attempt fails loud.
    def _no_net(*a, **k):
        raise AssertionError("air-gap violated: a network fetch was attempted")
    datafeeds.fetch = _no_net  # type: ignore[assignment]

    # 1) Signature scan (bundled DB, no network).
    inc = load_observations("11-multi-framework-incident/observations.json")
    scan = scan_observations(inc, threshold=35)
    flagged = sum(1 for r in scan if r.top is not None)
    print(f"\n  1. signature scan   : {flagged}/{len(scan)} hosts flagged "
          "(bundled DB)")

    # 2) Feed enrichment from the cached snapshot only.
    intel = [observation_from_record(r)
             for r in load_observations("13-threat-intel-feeds/observations.json")]
    feodo = feeds.feodo_c2_ips(offline=True)
    ja3bl = feeds.sslbl_ja3(offline=True)
    hits = sum(len(feeds.enrich_observation(o, feodo=feodo, ja3bl=ja3bl))
               for o in intel)
    print(f"  2. feed enrichment  : {hits} known-bad hit(s) from cached "
          f"snapshot ({len(feodo)} IPs / {len(ja3bl)} JA3s)")

    # 3) Correlation into campaigns.
    corr_recs = load_observations("14-campaign-correlation/observations.json")
    campaigns = correlate(scan_observations(corr_recs, threshold=35))
    clustered = sum(c.size for c in campaigns)
    print(f"  3. correlation      : {len(campaigns)} campaign(s), "
          f"{clustered} hosts clustered")

    # 4) SARIF export for the disconnected case file.
    sarif = to_sarif(scan)
    print(f"  4. SARIF export     : {len(sarif['runs'][0]['results'])} result(s), "
          f"version {sarif['version']}")

    print("\n  Every stage ran with the network hard-forbidden — no fetch was "
          "attempted, no byte left the enclave.")
    print("\nSneakernet the feed snapshot in with "
          "`c2detect feeds`-backed datafeeds snapshot-export/-import; everything "
          "else is bundled. This is the disconnected-network triage loop.")


if __name__ == "__main__":
    main()
