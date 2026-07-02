"""Scenario 23 - detection engineering: one DB, six SIEM/EDR rule dialects.

**Audience:** detection engineers who have to feed Sentinel, Splunk, Elastic
*and* the network sensors from a single source of truth.

The bundled fingerprint DB is the source of truth; this demo generates
deployable rules for all six supported targets — Sigma, Suricata, Microsoft
Sentinel/Defender KQL, Splunk SPL, Elastic EQL and YARA — and shows that every
one keys on the same documented Cobalt Strike fingerprints. Fully offline,
deterministic.
"""
from _common import rule
from c2detect.rules import generate


TARGETS = ["sigma", "suricata", "kql", "splunk", "eql", "yara"]
CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"
CS_JA3 = "a0e9f5d64349fb13191bc781f81f42e1"


def main() -> None:
    rule("MULTI-SIEM RULES  -  one signature DB, six detection dialects")

    print("\nGenerated rule bytes per target (all from the same DB):")
    for fmt in TARGETS:
        text = generate(fmt)
        # Sanity: the Cobalt Strike fingerprint shows up in every TLS-aware
        # dialect; YARA keys on config strings instead (no TLS hashes).
        has_fp = (CS_JARM in text) or (CS_JA3 in text) or ("Cobalt Strike" in text)
        print(f"   {fmt:<9}: {len(text):>6} bytes   "
              f"{'contains CS fingerprint' if has_fp else ''}")
        assert text.strip(), f"{fmt} produced nothing"
        assert has_fp, f"{fmt} lost the Cobalt Strike fingerprint"

    print("\nDeploy any of them:")
    print("   c2detect rules --format kql    > sentinel_hunt.kql")
    print("   c2detect rules --format splunk > c2_correlation.spl")
    print("   c2detect rules --format eql    > elastic_c2.eql")
    print("   c2detect rules --format yara   > c2_config.yar")


if __name__ == "__main__":
    main()
