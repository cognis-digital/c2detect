"""Scenario 19 - hunt automation: gate on a correlated *campaign*, not a host.

**Audience:** detection automation engineers.

A single noisy host is one thing; a *cluster* of hosts sharing operator infra is
an incident. This demo runs correlation over a week of telemetry and shows how a
pipeline can gate on the worst severity of any clustered campaign — so an
automated hunt escalates only when shared infrastructure (reused cert serial,
JARM) actually fuses multiple hosts, not on every lone detection. Uses the real
``correlate`` engine and reproduces the CLI's campaign-gate exit codes.
"""
from _common import load_observations, rule
from c2detect.core import scan_observations, SEVERITY_ORDER
from c2detect.correlate import correlate


def _campaign_gate_rc(campaigns, fail_on):
    """Reproduce the CLI correlate-gate contract."""
    if fail_on is not None:
        limit = SEVERITY_ORDER.get(fail_on, 9)
        gated = any(SEVERITY_ORDER.get(c.severity, 9) <= limit for c in campaigns)
        return 2 if gated else 0
    return 1 if campaigns else 0


def main() -> None:
    rule("CAMPAIGN GATE  -  escalate on shared infra, not a lone host")

    records = load_observations("14-campaign-correlation/observations.json")
    results = scan_observations(records, threshold=35)
    campaigns = correlate(results)

    total = sum(c.size for c in campaigns)
    print(f"\n{len(campaigns)} campaign(s) clustering {total} of {len(records)} "
          "hosts by shared infrastructure\n")
    for c in campaigns:
        fam = ", ".join(c.families) if c.families else "(unattributed)"
        print(f"  campaign #{c.cid}  [{c.severity.upper()}]  conf={c.confidence}  "
              f"hosts={c.size}  {fam}")

    print("\n  Pipeline gate outcomes:")
    for fail_on in ("critical", "high", "low", None):
        rc = _campaign_gate_rc(campaigns, fail_on)
        label = fail_on or "(any campaign)"
        verdict = ("HARD-FAIL" if rc == 2 else "campaigns found" if rc == 1
                   else "pass")
        print(f"    --fail-on {str(label):<14} ->  exit {rc}  [{verdict}]")

    print("\nDeploy:")
    print("   c2detect correlate week.json --fail-on critical")
    print("\nThe gate fires on a clustered campaign's severity — one operator "
          "estate across many hosts — so automation escalates the incident, not "
          "the noise.")


if __name__ == "__main__":
    main()
