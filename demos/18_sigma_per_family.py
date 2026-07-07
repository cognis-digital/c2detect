"""Scenario 18 - SIEM content: inspect a single generated Sigma rule.

**Audience:** SIEM content authors reviewing a rule before they ship it.

Demo 3 shows the bulk Sigma/Suricata export; this one zooms into a *single*
family so a content author can read the exact rule c2detect generates — its
stable UUID, log source, detection selections and ATT&CK tags — and confirm it's
deployable as-is. It renders the Cobalt Strike rule, verifies its structure, and
proves the UUID is deterministic across runs (so re-generating never churns your
rule IDs).
"""
from _common import rule
from c2detect.core import signatures
from c2detect.rules import sigma_rule


def main() -> None:
    rule("SIGMA PER-FAMILY  -  read one rule before you ship it")

    cs = next(s for s in signatures() if s.family == "Cobalt Strike")
    text = sigma_rule(cs)

    print("\nGenerated Sigma rule (Cobalt Strike):\n")
    for line in text.splitlines():
        print(f"   {line}")

    # Structural contract a content author cares about.
    print("\nReview checklist:")
    print(f"   has stable id           : {'id: ' in text}")
    print(f"   has logsource           : {'logsource:' in text}")
    print(f"   has detection+condition : "
          f"{'detection:' in text and 'condition:' in text}")
    print(f"   carries ATT&CK C2 tag   : {'attack.command_and_control' in text}")
    print(f"   keys on the CS JA3      : {cs.ja3[0] in text}")

    # Deterministic: the same DB renders byte-identical rules every run, so the
    # rule UUID never churns in version control.
    print(f"   deterministic re-render : {sigma_rule(cs) == text}")

    print("\nThe id is an MD5-derived UUID seeded by the family name, so it's "
          "stable forever — regenerate the pack and your SIEM rule IDs don't "
          "move.")


if __name__ == "__main__":
    main()
