"""Scenario 1 - SOC / blue team: triage a noisy egress export.

**Audience:** SOC analysts and blue teams.

An alert fires: "anomalous TLS to a handful of egress IPs." You have a JARM
sweep export and minutes to decide what's real. c2detect scores every host
against the bundled C2 signature DB and hands you a prioritized verdict — which
IPs are C2, which framework, and *why* — so you can escalate the two that
matter and clear the benign CDNs hiding among them.
"""
from _common import load_observations, rule, sev_tag
from c2detect.core import scan_observations


def main() -> None:
    rule("SOC TRIAGE  -  prioritize a JARM egress sweep in seconds")

    # A real threat-hunt export: 5 egress IPs, 2 of which are C2 hiding among
    # benign CDN/cloud endpoints (Fastly / Google / Microsoft JARMs).
    records = load_observations("12-threat-hunt-jarm-sweep/observations.json")
    print(f"\nInput: {len(records)} egress hosts from a JARM sweep "
          "(demos/12-threat-hunt-jarm-sweep)\n")

    results = scan_observations(records, threshold=35)

    flagged = [r for r in results if r.top is not None]
    clean = [r for r in results if r.top is None]

    print(f"Triage verdict: {len(flagged)} host(s) need eyes, "
          f"{len(clean)} clean.\n")
    for res in results:
        host = res.observation.host or "(unnamed)"
        top = res.top
        if top is None:
            print(f"  {'[CLEAN   ]':<10} {host:<16} no C2 indicators (benign egress)")
            continue
        indicators = ", ".join(sorted({i.klass for i in top.indicators}))
        print(f"  {sev_tag(top.severity)} {host:<16} {top.family} "
              f"({top.confidence}% · {indicators})")

    print("\nEscalation order (most severe, highest confidence first):")
    ranked = sorted(
        flagged,
        key=lambda r: (r.top.confidence, -len(r.top.indicators)),
        reverse=True,
    )
    for n, res in enumerate(ranked, 1):
        print(f"  {n}. {res.observation.host}  →  {res.top.family} "
              f"[{res.top.severity}]  conf {res.top.confidence}%")

    print("\nTwo C2 hosts pulled out of five; the CDN noise is cleared. "
          "Hand the ranked list to IR.")


if __name__ == "__main__":
    main()
