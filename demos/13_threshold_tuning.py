"""Scenario 13 - detection tuning: trade recall against false positives.

**Audience:** detection engineers calibrating c2detect for their estate.

The confidence threshold is the single knob between "catch everything, tolerate
noise" and "only high-confidence hits." This demo sweeps the threshold across a
mixed batch — real C2 plus a benign baseline — and shows how the flagged count
moves, so you can pick the floor that fits your tolerance. It uses the real
engine; nothing is simulated.
"""
from _common import load_observations, rule
from c2detect.core import scan_observations


def main() -> None:
    rule("THRESHOLD TUNING  -  recall vs. false positives, swept live")

    # A mixed batch: known C2 hosts + a benign CDN/cloud baseline.
    records = (load_observations("11-multi-framework-incident/observations.json")
               + load_observations("03-benign-baseline/observations.json"))
    print(f"\nMixed batch: {len(records)} observations "
          "(multi-framework incident + benign baseline)\n")

    print(f"  {'threshold':>9}   {'hosts flagged':>13}   {'total matches':>13}")
    print("  " + "-" * 41)
    prev = None
    for thr in (10, 25, 35, 50, 70, 90):
        results = scan_observations(records, threshold=thr)
        flagged = sum(1 for r in results if r.top is not None)
        matches = sum(r.count for r in results)
        arrow = ""
        if prev is not None and flagged < prev:
            arrow = "  <- fewer hosts as the floor rises"
        prev = flagged
        print(f"  {thr:>9}   {flagged:>13}   {matches:>13}{arrow}")

    print("\nThe default floor of 35 keeps strong single-fingerprint hits (a "
          "JARM alone clears it) while a stricter 70 demands corroboration. "
          "Tune to your noise budget:")
    print("   c2detect scan telemetry/ --threshold 50")


if __name__ == "__main__":
    main()
