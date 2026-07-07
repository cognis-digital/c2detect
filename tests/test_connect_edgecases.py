"""Coverage for c2detect.connect that does NOT require the soft cognis-connect dep.

``map_record`` is a pure dict transform and is always importable; ``emit_main``
has a clean missing-dependency path that returns 1 with a helpful message. Both
are tested here so the module is covered even on a base install.
"""

from __future__ import annotations

import importlib
import io
import sys

import pytest

connect = importlib.import_module("c2detect.connect")


# --------------------------------------------------------------------------- #
# map_record — pure transform, no dependency
# --------------------------------------------------------------------------- #
class TestMapRecord:
    def test_returns_dict(self):
        assert isinstance(connect.map_record({"title": "t"}), dict)

    def test_preserves_known_fields(self):
        rec = {"title": "T", "severity": "high", "type": "c2",
               "description": "d", "tags": ["a"], "ipv4": "1.2.3.4"}
        out = connect.map_record(rec)
        for k, v in rec.items():
            assert out[k] == v

    def test_passes_through_unknown_fields(self):
        out = connect.map_record({"weird": 1, "title": "t"})
        assert out["weird"] == 1

    def test_empty_record(self):
        assert connect.map_record({}) == {}

    def test_does_not_mutate_input(self):
        rec = {"title": "t"}
        connect.map_record(rec)
        assert rec == {"title": "t"}

    def test_maritime_fields_carried(self):
        out = connect.map_record({"imo": "1234567", "mmsi": "987654321",
                                  "lat": 1.0, "lon": 2.0})
        assert out["imo"] == "1234567" and out["lat"] == 1.0

    def test_source_constant(self):
        assert connect.SOURCE == "c2detect"


# --------------------------------------------------------------------------- #
# emit_main — missing-dependency path (no cognis_connect installed)
# --------------------------------------------------------------------------- #
class TestEmitMissingDep:
    def test_missing_dep_returns_1(self, monkeypatch, capsys):
        # Force the optional import to fail regardless of install state.
        import builtins
        real_import = builtins.__import__

        def _blocked(name, *a, **k):
            if name.startswith("cognis_connect"):
                raise ImportError("blocked for test")
            return real_import(name, *a, **k)

        monkeypatch.setattr(builtins, "__import__", _blocked)
        monkeypatch.setattr(sys, "stdin", io.StringIO('[{"title":"x"}]'))
        rc = connect.emit_main(["--to", "stix"])
        assert rc == 1
        assert "cognis-connect" in capsys.readouterr().err

    def test_unknown_target_argparse_error(self):
        # argparse rejects an out-of-choices --to before any import.
        with pytest.raises(SystemExit):
            connect.emit_main(["--to", "not-a-real-target"])
