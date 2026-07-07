"""Edge-case coverage for the self-check coverage engine.

Exercises a synthetic demos dir with malicious / benign / feature scenarios,
threshold sensitivity, the DEGRADED paths (a missed malicious scenario and a
benign false-positive), JSONL/text blob handling, and the render-table output —
all against tmp dirs so the bundled report is never disturbed.
"""

from __future__ import annotations

import pytest

from c2detect.selfcheck import (
    _families_in_blob,
    _is_benign,
    _is_feature,
    render_table,
    run_self_check,
)

CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"


def _scenario(root, name, payload):
    d = root / name
    d.mkdir()
    (d / "observations.json").write_text(payload, encoding="utf-8")
    return d


# --------------------------------------------------------------------------- #
# blob family extraction
# --------------------------------------------------------------------------- #
class TestBlobExtraction:
    def test_json_array_blob(self):
        fams = _families_in_blob(f'[{{"jarm": "{CS_JARM}"}}]', 35)
        assert "Cobalt Strike" in fams

    def test_free_text_blob(self):
        fams = _families_in_blob(f"saw {CS_JARM} on wire", 35)
        assert "Cobalt Strike" in fams

    def test_jsonl_blob(self):
        blob = f'{{"jarm": "{CS_JARM}"}}\n{{"host": "x", "port": 12345}}'
        fams = _families_in_blob(blob, 35)
        assert "Cobalt Strike" in fams

    def test_benign_blob_empty(self):
        assert _families_in_blob('[{"host": "x", "port": 12345}]', 35) == set()

    def test_threshold_filters(self):
        # A lone port hit clears 0 but not 90.
        assert _families_in_blob('[{"port": 50050}]', 0)
        assert _families_in_blob('[{"port": 50050}]', 90) == set()


# --------------------------------------------------------------------------- #
# scenario kind classification
# --------------------------------------------------------------------------- #
class TestKindClassification:
    @pytest.mark.parametrize("name", ["03-benign-baseline", "benign", "BASELINE"])
    def test_benign_names(self, name):
        assert _is_benign(name)

    @pytest.mark.parametrize("name", ["01-cobalt-strike", "04-sliver"])
    def test_non_benign_names(self, name):
        assert not _is_benign(name)

    @pytest.mark.parametrize("name", ["13-threat-intel-feeds", "campaign",
                                      "14-correlation"])
    def test_feature_names(self, name):
        assert _is_feature(name)


# --------------------------------------------------------------------------- #
# end-to-end on synthetic demo dirs
# --------------------------------------------------------------------------- #
class TestSyntheticDirs:
    def test_healthy_when_malicious_fires_and_benign_quiet(self, tmp_path):
        _scenario(tmp_path, "01-cs", f'[{{"jarm": "{CS_JARM}"}}]')
        _scenario(tmp_path, "02-benign-baseline",
                  '[{"host": "x", "port": 12345}]')
        report = run_self_check(demos_dir=str(tmp_path))
        assert report["healthy"] is True
        assert report["malicious_detected"] == 1
        assert report["benign_clean"] == 1

    def test_degraded_when_malicious_misses(self, tmp_path):
        # A "signature" scenario that contains nothing detectable -> MISS.
        _scenario(tmp_path, "01-empty", '[{"host": "x", "port": 12345}]')
        report = run_self_check(demos_dir=str(tmp_path))
        assert report["healthy"] is False
        assert report["malicious_detected"] == 0

    def test_degraded_when_benign_false_positive(self, tmp_path):
        _scenario(tmp_path, "01-benign-baseline", f'[{{"jarm": "{CS_JARM}"}}]')
        report = run_self_check(demos_dir=str(tmp_path))
        # A benign baseline that fires is a false positive -> DEGRADED.
        assert report["healthy"] is False

    def test_feature_scenario_is_informational(self, tmp_path):
        _scenario(tmp_path, "13-threat-intel-feeds",
                  '[{"host": "1.2.3.4"}]')
        report = run_self_check(demos_dir=str(tmp_path))
        assert report["feature_scenarios"] == 1
        # A feature scenario does not gate health.
        assert report["healthy"] is True

    def test_missing_demos_dir_is_safe(self, tmp_path):
        report = run_self_check(demos_dir=str(tmp_path / "nope"))
        assert report["scenarios_total"] == 0
        assert report["healthy"] is True

    def test_known_family_count_matches_db(self, tmp_path):
        report = run_self_check(demos_dir=str(tmp_path))
        assert report["known_family_count"] >= 12


# --------------------------------------------------------------------------- #
# render_table
# --------------------------------------------------------------------------- #
class TestRenderTable:
    def test_contains_status_line(self, tmp_path):
        _scenario(tmp_path, "01-cs", f'[{{"jarm": "{CS_JARM}"}}]')
        out = render_table(run_self_check(demos_dir=str(tmp_path)))
        assert "HEALTHY" in out

    def test_degraded_status_rendered(self, tmp_path):
        _scenario(tmp_path, "01-empty", '[{"host": "x", "port": 12345}]')
        out = render_table(run_self_check(demos_dir=str(tmp_path)))
        assert "DEGRADED" in out

    def test_benign_clean_label(self, tmp_path):
        _scenario(tmp_path, "01-benign-baseline",
                  '[{"host": "x", "port": 12345}]')
        out = render_table(run_self_check(demos_dir=str(tmp_path)))
        assert "CLEAN" in out
