"""Scenario 14 - coverage review: audit what the signature DB actually covers.

**Audience:** detection leads doing a coverage / gap review.

Before you trust a detector you want to know what it knows. This demo walks the
bundled signature DB via the public ``list_signatures`` accessor and prints a
coverage table — every C2 family, its severity, and which indicator classes
(JARM/JA3/JA4/cert/URI/beacon…) back it — so a detection lead can see at a glance
where coverage is strong (full TLS fingerprint) versus heuristic (port/URI only).
"""
from _common import rule
from c2detect.core import list_signatures
from c2detect.core import SEVERITY_ORDER


def main() -> None:
    rule("SIGNATURE INVENTORY  -  what does the DB actually cover?")

    rows = list_signatures()
    rows.sort(key=lambda r: (SEVERITY_ORDER.get(r["severity"], 9), r["family"]))
    print(f"\n{len(rows)} C2 families in the bundled signature DB\n")

    by_sev: dict[str, int] = {}
    strong = 0
    print(f"  {'FAMILY':<28} {'SEV':<9} INDICATORS")
    print("  " + "-" * 70)
    for r in rows:
        ic = r["indicator_counts"]
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
        # "strong" coverage = at least one decisive TLS fingerprint class.
        if any(k in ic for k in ("ja4", "ja4s", "jarm", "ja3", "ja3s", "ja4x")):
            strong += 1
        shown = ", ".join(f"{k}:{v}" for k, v in ic.items())
        print(f"  {r['family']:<28} {r['severity']:<9} {shown}")

    print("\n  Coverage summary:")
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in by_sev:
            print(f"    {sev:<9}: {by_sev[sev]} families")
    print(f"    families backed by a TLS fingerprint (decisive): "
          f"{strong}/{len(rows)}")

    print("\nThe families backed only by port/URI heuristics are where you'd add "
          "a captured JARM/JA4 next. That's your coverage roadmap, generated from "
          "the DB itself.")


if __name__ == "__main__":
    main()
