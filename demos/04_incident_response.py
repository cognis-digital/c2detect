"""Scenario 4 - incident response: attribute every stage of an intrusion.

**Audience:** incident responders / DFIR.

One intrusion rarely uses one tool. This demo replays telemetry from a single
incident where the operator staged **four** different C2 frameworks — Cobalt
Strike, Sliver, Havoc, and the fast-growing AdaptixC2 — and shows c2detect
attributing each beacon to its framework with the exact indicators that fired.
The result is the per-host "what is this, and how sure are we" table that goes
straight into the incident timeline.
"""
from _common import load_observations, rule, sev_tag
from c2detect.core import scan_observations


def main() -> None:
    rule("INCIDENT RESPONSE  -  attribute a multi-framework intrusion")

    records = load_observations("11-multi-framework-incident/observations.json")
    print(f"\nInput: {len(records)} hosts seen during one intrusion "
          "(demos/11-multi-framework-incident)\n")

    results = scan_observations(records, threshold=35)

    attributed = []
    for res in results:
        host = res.observation.host or "(unnamed)"
        top = res.top
        if top is None:
            print(f"  {'[CLEAN   ]':<10} {host:<14} unattributed")
            continue
        attributed.append(top.family)
        print(f"  {sev_tag(top.severity)} {host:<14} {top.family:<24} "
              f"conf {top.confidence}%")
        for ind in top.indicators:
            print(f"             - {ind.klass:<11} {ind.matched}")

    families = sorted(set(attributed))
    print(f"\nTimeline summary: {len(attributed)} beacon(s) across "
          f"{len(families)} framework(s):")
    for fam in families:
        print(f"   • {fam}")

    print("\nFour frameworks, one operator, one timeline — each stage "
          "attributed by the indicators that actually matched. No guessing.")


if __name__ == "__main__":
    main()
