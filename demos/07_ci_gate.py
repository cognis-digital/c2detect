"""Scenario 7 - DevSecOps: fail a pipeline on a critical C2 detection.

**Audience:** DevSecOps / release engineers.

c2detect is exit-code aware so it drops straight into a CI gate. A clean scan
exits 0; any match exits 1; and ``--fail-on <severity>`` exits 2 only when a
finding lands at or above a severity floor you choose — so you can let *low*
heuristics through while hard-failing the build on a *critical* Cobalt Strike
hit. This demo exercises the real gating logic (``fails_gate``) across three
inputs and shows the exit code each would return in a pipeline.
"""
from _common import load_observations, rule
from c2detect.core import scan_observations, fails_gate, worst_severity


def _gate_rc(results, fail_on):
    """Reproduce the CLI's exit-code contract for a set of results."""
    if fail_on is not None:
        return 2 if fails_gate(results, fail_on) else 0
    return 1 if any(r.count for r in results) else 0


def main() -> None:
    rule("CI GATE  -  exit codes that hard-fail a pipeline on critical C2")

    cases = [
        ("benign baseline", "03-benign-baseline/observations.json", "critical"),
        ("cobalt strike   ", "01-cobalt-strike-network/observations.json", "critical"),
        ("sliver (high)   ", "04-sliver-mtls/observations.json", "critical"),
    ]

    print("\n  fail-on=critical: only a critical finding should hard-fail (rc 2)\n")
    for label, path, fail_on in cases:
        results = scan_observations(load_observations(path), threshold=35)
        worst = worst_severity(results) or "clean"
        rc = _gate_rc(results, fail_on)
        verdict = ("HARD-FAIL" if rc == 2 else "pass" if rc == 0 else "findings")
        print(f"  {label}  worst={worst:<9} --fail-on={fail_on}  ->  "
              f"exit {rc}  [{verdict}]")

    print("\n  Without --fail-on, any match exits 1 (advisory), clean exits 0:\n")
    for label, path, _ in cases:
        results = scan_observations(load_observations(path), threshold=35)
        rc = _gate_rc(results, None)
        print(f"  {label}  ->  exit {rc}")

    print("\nDeploy in CI:")
    print("   c2detect scan telemetry/ --fail-on critical   # break the build")
    print("\nCritical C2 breaks the build; lower-severity heuristics stay "
          "advisory. The gate is yours to set.")


if __name__ == "__main__":
    main()
