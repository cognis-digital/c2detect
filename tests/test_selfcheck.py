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


def test_self_check_ignores_non_scenario_dirs(tmp_path):
    # A __pycache__ / dotfile dir (e.g. left by running the Python demos) must
    # never be counted as a scenario or it would show as a phantom MISS.
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "x.pyc").write_bytes(b"\x00")
    (tmp_path / ".hidden").mkdir()
    (tmp_path / "01-real").mkdir()
    (tmp_path / "01-real" / "observations.json").write_text(
        '[{"ip": "1.2.3.4", "port": 50050, '
        '"jarm": "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"}]',
        encoding="utf-8")
    report = run_self_check(demos_dir=str(tmp_path))
    names = {s["scenario"] for s in report["scenarios"]}
    assert names == {"01-real"}
    assert report["healthy"] is True
