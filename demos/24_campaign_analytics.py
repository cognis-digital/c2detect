"""Scenario 24 - intel: rank the estate — hub host, density, linchpin pivot.

**Audience:** IR leads deciding which host to pull first and which indicator to
block to fragment an adversary's estate.

Clustering hosts into a campaign is step one; step two is knowing *where to
apply pressure*. This demo runs the correlation engine over a multi-host
campaign fixture, then computes graph analytics: the hub host (highest degree —
often the shared redirector/team-server), the cluster density, and the linchpin
pivot (the single heaviest shared value — rotate/block it and the estate
splinters). Fully offline.
"""
from _common import load_observations, rule
from c2detect.core import scan_observations
from c2detect.correlate import correlate, analytics


def main() -> None:
    rule("CAMPAIGN ANALYTICS  -  hub host, density, and the linchpin pivot")

    records = load_observations("14-campaign-correlation/observations.json")
    results = scan_observations(records, threshold=35)
    campaigns = correlate(results)
    roll = analytics(campaigns)

    print(f"\nCampaigns          : {roll['campaign_count']}")
    print(f"Hosts clustered    : {roll['host_count']}")
    print(f"Largest campaign   : {roll['largest_campaign']} hosts")
    if roll["family_prevalence"]:
        print(f"Family prevalence  : "
              + ", ".join(f"{k} x{v}" for k, v in roll["family_prevalence"].items()))

    for c in roll["campaigns"]:
        print(f"\n== Campaign #{c['campaign_id']}  "
              f"({c['size']} hosts, density {c['density']})")
        print(f"   hub host        : {c['hub_host']}  "
              f"(the pivot to hunt from first)")
        lp = c["linchpin_pivot"]
        if lp:
            print(f"   linchpin pivot  : {lp['class']} = {lp['value'][:40]}"
                  f"{'...' if len(lp['value']) > 40 else ''}  (w={lp['weight']})")
        print(f"   ATT&CK          : {', '.join(c['attack_techniques'])}")

    assert roll["campaign_count"] >= 1
    assert roll["campaigns"][0]["hub_host"]
    assert roll["campaigns"][0]["linchpin_pivot"] is not None

    print("\nRun it:")
    print("   c2detect correlate week.json --format json --analytics")
    print("\nBlock the linchpin, pull the hub — the rest of the estate loses "
          "its shared infrastructure.")


if __name__ == "__main__":
    main()
