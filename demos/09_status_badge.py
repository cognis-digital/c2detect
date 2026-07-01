"""Scenario 9 - repo hygiene: a shields.io status badge from a scan.

**Audience:** maintainers who want a live "is my egress clean?" badge.

c2detect emits a shields.io *endpoint* JSON whose colour and message reflect the
worst severity found — green "clean" when nothing matched, red/critical when a
team server is hiding in your traffic. Point a shields.io endpoint badge at the
JSON your nightly scan publishes and the repo README shows the current verdict.
This demo renders the badge for a clean baseline and for a live detection.
"""
from _common import load_observations, rule
from c2detect.core import scan_observations, to_badge


def main() -> None:
    rule("STATUS BADGE  -  shields.io endpoint JSON from a scan")

    cases = [
        ("clean baseline", "03-benign-baseline/observations.json"),
        ("cobalt strike ", "01-cobalt-strike-network/observations.json"),
        ("multi-framework", "11-multi-framework-incident/observations.json"),
    ]

    print()
    for label, path in cases:
        results = scan_observations(load_observations(path), threshold=35)
        badge = to_badge(results)
        # Contract: a shields endpoint badge is schemaVersion 1 + label/message/color.
        assert badge["schemaVersion"] == 1
        assert badge["label"] == "c2detect"
        print(f"  {label}  ->  color={badge['color']:<11} "
              f"message='{badge['message']}'")

    print("\nDeploy:")
    print("   c2detect scan egress/ --format badge > badge.json   # nightly")
    print("   # README:")
    print("   ![c2detect](https://img.shields.io/endpoint?url=<raw badge.json>)")
    print("\nGreen means your captured egress is clean; red means a C2 "
          "fingerprint is sitting in it. Live, in the README.")


if __name__ == "__main__":
    main()
