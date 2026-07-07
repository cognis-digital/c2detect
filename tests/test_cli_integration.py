"""End-to-end CLI integration matrix over every bundled demo fixture.

Each scenario fixture is run through ``scan`` in all output formats and through
``correlate``, asserting the output is well-formed and the exit code obeys the
documented contract. This is the broad smoke net that proves the whole pipeline
survives every shipped telemetry shape. Fully offline (no --feeds, no network).
"""

from __future__ import annotations

import glob
import json
import os

import pytest

from c2detect.cli import main

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS_DIR = os.path.join(REPO_ROOT, "demos")

FIXTURES = sorted(
    glob.glob(os.path.join(DEMOS_DIR, "*", "observations.json"))
)
# Friendly ids: the parent directory name.
FIXTURE_IDS = [os.path.basename(os.path.dirname(p)) for p in FIXTURES]

# Fixtures that contain at least one C2 match (everything except the benign /
# pure-feed scenarios). Verified empirically below in test_known_classification.
BENIGN_OR_FEEDONLY = {"03-benign-baseline", "13-threat-intel-feeds"}


@pytest.mark.parametrize("path", FIXTURES, ids=FIXTURE_IDS)
def test_scan_json_well_formed(path, capsys):
    rc = main(["scan", path, "--format", "json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["tool"] == "c2detect"
    assert "results" in data and isinstance(data["results"], list)
    # rc is 0 (clean) or 1 (findings); never an error here.
    assert rc in (0, 1)


@pytest.mark.parametrize("path", FIXTURES, ids=FIXTURE_IDS)
def test_scan_sarif_valid(path, capsys):
    main(["scan", path, "--format", "sarif"])
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    referenced = {r["ruleId"] for r in run["results"]}
    assert referenced <= declared


@pytest.mark.parametrize("path", FIXTURES, ids=FIXTURE_IDS)
def test_scan_badge_valid(path, capsys):
    main(["scan", path, "--format", "badge"])
    data = json.loads(capsys.readouterr().out)
    assert data["schemaVersion"] == 1
    assert data["label"] == "c2detect"


@pytest.mark.parametrize("path", FIXTURES, ids=FIXTURE_IDS)
def test_scan_html_self_contained(path, capsys):
    main(["scan", path, "--format", "html"])
    out = capsys.readouterr().out
    assert "<!doctype html>" in out.lower()
    assert 'src="http' not in out


@pytest.mark.parametrize("path", FIXTURES, ids=FIXTURE_IDS)
def test_scan_table_renders(path, capsys):
    rc = main(["scan", path, "--format", "table"])
    out = capsys.readouterr().out
    assert "c2detect:" in out
    assert rc in (0, 1)


@pytest.mark.parametrize("path", FIXTURES, ids=FIXTURE_IDS)
def test_correlate_json_well_formed(path, capsys):
    rc = main(["correlate", path, "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["mode"] == "correlate"
    assert "campaigns" in data
    assert rc in (0, 1)


@pytest.mark.parametrize("path", FIXTURES, ids=FIXTURE_IDS)
def test_correlate_dot_valid(path, capsys):
    main(["correlate", path, "--format", "dot"])
    out = capsys.readouterr().out
    assert out.startswith("graph c2campaigns {")
    assert out.rstrip().endswith("}")


@pytest.mark.parametrize("path", FIXTURES, ids=FIXTURE_IDS)
def test_known_classification(path, capsys):
    """Malicious fixtures yield findings (rc 1); benign/feed-only stay clean."""
    rc = main(["scan", path, "--format", "json"])
    name = os.path.basename(os.path.dirname(path))
    if name in BENIGN_OR_FEEDONLY:
        assert rc == 0, f"{name} unexpectedly flagged"
    else:
        assert rc == 1, f"{name} should have flagged a C2 family"
