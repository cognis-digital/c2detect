"""Smoke test for the native cognis-connect emit (`c2detect.connect`)."""
from __future__ import annotations

import importlib
import io
import sys

import pytest

cc = pytest.importorskip("cognis_connect")          # optional [connect] extra
mod = importlib.import_module("c2detect.connect")


def test_map_record_returns_dict():
    out = mod.map_record({"title": "t", "severity": "high", "ip": "203.0.113.5"})
    assert isinstance(out, dict)


def test_findings_to_stix_bundle():
    fs = mod._findings('[{"title": "x", "severity": "high", "ip": "203.0.113.5"}]')
    bundle = cc.stix.to_bundle(fs)
    assert bundle["type"] == "bundle" and bundle["objects"]


def test_emit_sigma_from_stdin(capsys):
    sys.stdin = io.StringIO('[{"title": "x", "severity": "low", "domain": "evil.example"}]')
    try:
        rc = mod.emit_main(["--to", "sigma"])
    finally:
        sys.stdin = sys.__stdin__
    assert rc == 0 and "title:" in capsys.readouterr().out
