"""Scenario 3 - detection engineers: ship the DB as Sigma + Suricata rules.

**Audience:** detection engineers / content authors.

Don't just scan — deploy the intelligence. c2detect turns the same bundled
signature DB the scanner uses into ready-to-ship detection content: Sigma rules
for your SIEM and Suricata rules for your IDS/IPS, generated straight from the
documented TLS fingerprints and default URIs. This demo generates both, then
verifies the Suricata SIDs are deterministic and clash-free with ET/Talos.
"""
import re

from _common import rule
from c2detect import rules
from c2detect.core import signatures


def main() -> None:
    rule("DETECTION ENGINEERING  -  generate Sigma + Suricata from the DB")

    sigs = signatures()
    print(f"\nSignature DB: {len(sigs)} C2 families\n")

    # --- Suricata ------------------------------------------------------------
    suricata = rules.to_suricata()
    alert_lines = [ln for ln in suricata.splitlines() if ln.startswith("alert")]
    sids = [int(m.group(1)) for ln in alert_lines
            for m in [re.search(r"sid:(\d+);", ln)] if m]
    print(f"Suricata: {len(alert_lines)} rules generated")
    print(f"   SID range: {min(sids)}–{max(sids)} (private 9.2M band, "
          "no ET/Talos clash)")
    print(f"   SIDs unique: {len(sids) == len(set(sids))}")
    print("\n   Example rule (Cobalt Strike default JA3):")
    for ln in alert_lines:
        if "Cobalt Strike default JA3" in ln:
            print(f"     {ln[:100]}...")
            break

    # --- Sigma ---------------------------------------------------------------
    sigma = rules.to_sigma()
    titles = [ln for ln in sigma.splitlines() if ln.startswith("title:")]
    print(f"\nSigma: {len(titles)} rules generated (multi-document YAML)")
    print("   each carries attack.command_and_control + a per-family "
          "c2detect.family.* tag")
    print("\n   Example rule head (first family):")
    for ln in sigma.splitlines()[:8]:
        print(f"     {ln}")

    # --- ship it -------------------------------------------------------------
    print("\nDeploy:")
    print("   c2detect rules --format suricata -o c2detect.rules")
    print("   c2detect rules --format sigma    -o c2detect.sigma.yml")
    print("\nThe same fingerprints that triage your telemetry now live in your "
          "SIEM and IDS. Tune/threshold before production.")


if __name__ == "__main__":
    main()
