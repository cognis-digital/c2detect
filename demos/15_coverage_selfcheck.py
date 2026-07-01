"""Scenario 15 - QA / release gate: the bundled self-check coverage report.

**Audience:** maintainers / release engineers proving the detector still works.

c2detect ships a self-check that scans every bundled scenario and confirms two
things: each *malicious* scenario still fires, and each *benign* baseline stays
quiet (no false positives). It's the regression surface behind the coverage
badge and the CI gate. This demo runs the real ``run_self_check`` and prints the
HEALTHY/DEGRADED verdict the release gate keys on.
"""
from _common import rule
from c2detect.selfcheck import run_self_check, render_table


def main() -> None:
    rule("SELF-CHECK COVERAGE  -  malicious fires, benign stays quiet")

    report = run_self_check()
    print()
    print(render_table(report))

    print()
    print(f"  known families       : {report['known_family_count']}")
    print(f"  families exercised   : {report['families_exercised_count']}")
    print(f"  malicious detected   : {report['malicious_detected']}"
          f"/{report['malicious_scenarios']}")
    print(f"  benign kept clean    : {report['benign_clean']}"
          f"/{report['benign_scenarios']}")
    print(f"  verdict              : "
          f"{'HEALTHY' if report['healthy'] else 'DEGRADED'}")

    # The release gate: HEALTHY means every malicious scenario fired AND every
    # benign baseline stayed quiet.
    assert report["healthy"], "self-check DEGRADED — a regression slipped in"

    print("\nDeploy as a CI gate:")
    print("   c2detect self-check        # exit 0 only when HEALTHY")
    print("\nGreen here means the bundled DB still catches every documented "
          "framework and raises zero false positives on the baselines.")


if __name__ == "__main__":
    main()
