"""Smoke tests for the audience demo scenarios in ``demos/``.

Each demo loads a bundled telemetry fixture, runs the real c2detect engine fully
offline, prints narrated output, and must exit cleanly. These tests import each
scenario module and call ``main()``, asserting it runs without raising and emits
the expected narration — so the demos can never silently rot.
"""
from __future__ import annotations

import importlib
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS_DIR = os.path.join(REPO_ROOT, "demos")

# Ensure `import 01_soc_triage` (etc.) resolves against demos/.
sys.path.insert(0, DEMOS_DIR)

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


@pytest.fixture(autouse=True)
def _offline_feeds_cache(monkeypatch):
    """Point the feed cache at the bundled offline snapshot and forbid network."""
    snapshot = os.path.join(DEMOS_DIR, "13-threat-intel-feeds")
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", snapshot)
    import c2detect.datafeeds as df

    def _no_net(*a, **k):  # pragma: no cover - guard
        raise AssertionError("demo attempted network access")

    monkeypatch.setattr(df, "fetch", _no_net)
    yield


@pytest.mark.parametrize("name", SCENARIOS)
def test_demo_runs_and_narrates(name, capsys):
    mod = importlib.import_module(name)
    mod.main()  # must not raise
    out = capsys.readouterr().out
    assert out.strip(), f"{name} produced no output"
    # Every demo prints a banner rule and references c2detect concepts.
    assert "=" * 20 in out


def test_run_all_executes_every_scenario(capsys):
    run_all = importlib.import_module("run_all")
    run_all.main()
    out = capsys.readouterr().out
    assert "All c2detect demo scenarios completed." in out


def test_run_all_lists_twenty_scenarios():
    """run_all and the demo test list must stay in lock-step at 20 scenarios."""
    run_all = importlib.import_module("run_all")
    assert run_all.SCENARIOS == SCENARIOS
    assert len(SCENARIOS) == 20


def test_every_scenario_module_file_exists():
    for name in SCENARIOS:
        assert os.path.isfile(os.path.join(DEMOS_DIR, name + ".py")), name


def test_each_scenario_has_an_audience_docstring():
    """Every audience demo documents who it is for (the 'Audience:' marker)."""
    for name in SCENARIOS:
        mod = importlib.import_module(name)
        assert mod.__doc__ and "Audience:" in mod.__doc__, name


def test_common_helpers_load_real_fixtures():
    common = importlib.import_module("_common")
    records = common.load_observations("11-multi-framework-incident/observations.json")
    assert isinstance(records, list) and len(records) == 4
    assert os.path.isdir(common.FEEDS_SNAPSHOT)
    assert common.sev_tag("critical") == "[CRITICAL]"


def test_soc_triage_separates_c2_from_benign():
    common = importlib.import_module("_common")
    from c2detect.core import scan_observations

    records = common.load_observations("12-threat-hunt-jarm-sweep/observations.json")
    results = scan_observations(records, threshold=35)
    flagged = [r for r in results if r.top is not None]
    clean = [r for r in results if r.top is None]
    # 2 of 5 egress hosts are C2 (Sliver + Cobalt Strike); 3 are benign CDNs.
    assert len(flagged) == 2
    assert len(clean) == 3
    families = {r.top.family for r in flagged}
    assert "Sliver" in families
