"""Tests for the self-check coverage feature."""

from __future__ import annotations

from c2detect.selfcheck import run_self_check, render_table


def test_self_check_runs_and_exercises_frameworks():
    report = run_self_check()
    # The bundled demos must exist and exercise multiple documented frameworks.
    assert report["scenarios_total"] >= 10
    assert report["families_exercised_count"] >= 5
    assert report["known_family_count"] >= 5
    # Every malicious scenario should fire at least one detection.
    assert report["malicious_detected"] == report["malicious_scenarios"]


def test_self_check_quiet_on_benign_baseline():
    report = run_self_check()
    # If a benign baseline scenario is shipped, it must stay quiet (no FP).
    if report["benign_scenarios"]:
        assert report["benign_clean"] == report["benign_scenarios"]
    assert report["healthy"] is True


def test_render_table_is_string():
    out = render_table(run_self_check())
    assert "self-check" in out
    assert "frameworks exercised" in out
