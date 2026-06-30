"""Scenario 5 - threat hunters: cluster hosts into campaigns by shared infra.

**Audience:** threat hunters / intel teams mapping an adversary's estate.

One detection says "this host looks like Cobalt Strike." Correlation answers the
question that drives the hunt: *which* of your hosts are the same operator's
infrastructure, and *why*. Adversaries rotate IPs cheaply but the shape of their
listener + cert stack is expensive to change, so it leaks across the estate.
This demo clusters a week of telemetry on literally-shared pivots (reused cert
serial, JARM, …) with union-find and prints the evidence inline.
"""
from _common import load_observations, rule
from c2detect.core import scan_observations
from c2detect.correlate import correlate, PIVOT_WEIGHTS


def main() -> None:
    rule("CAMPAIGN CORRELATION  -  which hosts are one operator's estate")

    records = load_observations("14-campaign-correlation/observations.json")
    print(f"\nInput: {len(records)} hosts of weekly telemetry "
          "(demos/14-campaign-correlation)\n")

    results = scan_observations(records, threshold=35)
    campaigns = correlate(results)

    total = sum(c.size for c in campaigns)
    print(f"{len(campaigns)} shared-infrastructure campaign(s) clustering "
          f"{total} of {len(records)} hosts:\n")

    for c in campaigns:
        fam = ", ".join(c.families) if c.families else "(unattributed)"
        print(f"  == Campaign #{c.cid}  [{c.severity.upper()}]  "
              f"confidence={c.confidence}  hosts={c.size}  families: {fam}")
        for h in c.hosts:
            print(f"       host: {h}")
        print("       shared infrastructure pivots (heaviest first):")
        for klass in sorted(c.shared, key=lambda k: -PIVOT_WEIGHTS.get(k, 0)):
            vals = c.shared[klass]
            shown = ", ".join(vals[:2]) + (" …" if len(vals) > 2 else "")
            print(f"         - {klass} (w={PIVOT_WEIGHTS.get(klass, 0)}): {shown}")
        print()

    singletons = len(records) - total
    print(f"{singletons} host(s) shared no infrastructure pivot above the edge "
          "floor — left isolated (a lone shared port never fuses hosts).")
    print("Every pivot reported is a value two hosts *literally* share — no "
          "actor attribution, nothing invented.")


if __name__ == "__main__":
    main()
