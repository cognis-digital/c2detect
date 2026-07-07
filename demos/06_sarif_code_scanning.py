"""Scenario 6 - AppSec / platform: emit SARIF for GitHub code-scanning.

**Audience:** application-security / platform engineers wiring c2detect into CI.

A scan is only as useful as where its results land. c2detect renders every
finding as SARIF 2.1.0 — the format GitHub code-scanning, Azure DevOps and most
SIEM ingesters speak natively — so a C2 detection shows up as an annotated alert
in the same UI your SAST/DAST results already use. This demo scans a
multi-framework incident, produces a valid SARIF log, and verifies the rule and
result objects line up (one rule per family, one result per match).
"""
from _common import load_observations, rule
from c2detect.core import scan_observations, to_sarif


def main() -> None:
    rule("SARIF / CODE-SCANNING  -  C2 findings as first-class CI alerts")

    records = load_observations("11-multi-framework-incident/observations.json")
    results = scan_observations(records, threshold=35)
    sarif = to_sarif(results)

    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    rules_out = driver["rules"]
    findings = run["results"]

    print(f"\nSARIF version : {sarif['version']}")
    print(f"Tool          : {driver['name']} {driver['version']}")
    print(f"Rules emitted : {len(rules_out)} (one per C2 family that fired)")
    print(f"Results       : {len(findings)} (one per match)\n")

    # Every result must reference a declared rule — that is the SARIF contract.
    declared = {r["id"] for r in rules_out}
    referenced = {r["ruleId"] for r in findings}
    orphans = referenced - declared
    print(f"All results reference a declared rule: {not orphans}")
    print(f"SARIF levels used: {sorted({r['level'] for r in findings})}\n")

    print("Per-finding alerts (as they'd appear in code-scanning):")
    for r in findings:
        loc = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        conf = r["properties"]["confidence"]
        print(f"  [{r['level']:7}] {loc:<16} {r['ruleId']}  (conf {conf}%)")

    print("\nDeploy:")
    print("   c2detect scan obs.json --format sarif > c2.sarif")
    print("   # then upload via github/codeql-action/upload-sarif")
    print("\nC2 detections now live next to your SAST/DAST alerts — same UI, "
          "same triage workflow, no new console.")


if __name__ == "__main__":
    main()
