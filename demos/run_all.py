"""Run every c2detect demo scenario end to end.

    python demos/run_all.py

Each scenario is independent, loads its own bundled telemetry fixture, runs the
real c2detect engine fully offline, prints narrated output, and exits 0 — so
they double as smoke tests for the public API.
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SCENARIOS = [
    "01_soc_triage",
    "02_threat_intel_feeds",
    "03_detection_rules",
    "04_incident_response",
    "05_campaign_correlation",
    "06_sarif_code_scanning",
    "07_ci_gate",
    "08_html_report",
    "09_status_badge",
    "10_jsonl_streaming",
    "11_freetext_telemetry",
    "12_correlation_graph",
    "13_threshold_tuning",
    "14_signature_inventory",
    "15_coverage_selfcheck",
    "16_feeds_plus_signatures",
    "17_beacon_cadence",
    "18_sigma_per_family",
    "19_correlate_gate",
    "20_air_gap_workflow",
]


def main() -> None:
    for name in SCENARIOS:
        mod = importlib.import_module(name)
        mod.main()
    print("\n" + "=" * 72)
    print("  All c2detect demo scenarios completed.")
    print("=" * 72)


if __name__ == "__main__":
    main()
