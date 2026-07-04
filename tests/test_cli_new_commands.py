"""CLI integration tests for the export / beacon subcommands, the new rule
formats, and correlate --analytics. All offline; drives main() directly."""
from __future__ import annotations

import io
import json

import pytest

from c2detect.cli import main

CS = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"


def _run(argv, stdin=None, monkeypatch=None):
    if stdin is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    return main(argv)


# ------------------------------------------------------------------- rules fmts
@pytest.mark.parametrize("fmt", ["kql", "splunk", "eql", "yara"])
def test_rules_new_formats(fmt, capsys):
    rc = main(["rules", "--format", fmt])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.strip()


def test_rules_write_to_file(tmp_path, capsys):
    out = tmp_path / "rules.yara"
    rc = main(["rules", "--format", "yara", "-o", str(out)])
    assert rc == 0
    assert out.read_text(encoding="utf-8").startswith("/*")


# -------------------------------------------------------------------- export
def test_export_db_stix(capsys):
    rc = main(["export", "--db", "--format", "stix"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["type"] == "bundle"
    assert any(o["type"] == "malware" for o in doc["objects"])


def test_export_db_misp_rejected(capsys):
    rc = main(["export", "--db", "--format", "misp"])
    assert rc == 2
    assert "STIX only" in capsys.readouterr().err


def test_export_stix_from_stdin(capsys, monkeypatch):
    rc = _run(["export", "--format", "stix"],
              stdin=json.dumps({"host": "1.2.3.4", "jarm": CS}),
              monkeypatch=monkeypatch)
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert any(o["type"] == "indicator" for o in doc["objects"])


def test_export_misp_from_stdin(capsys, monkeypatch):
    rc = _run(["export", "--format", "misp", "--event-info", "Custom"],
              stdin=json.dumps({"host": "1.2.3.4", "jarm": CS}),
              monkeypatch=monkeypatch)
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["Event"]["info"] == "Custom"


def test_export_to_file(tmp_path, capsys, monkeypatch):
    out = tmp_path / "bundle.json"
    rc = _run(["export", "--format", "stix", "-o", str(out)],
              stdin=json.dumps({"jarm": CS}), monkeypatch=monkeypatch)
    assert rc == 0
    json.loads(out.read_text(encoding="utf-8"))  # valid JSON


# -------------------------------------------------------------------- beacon
def test_beacon_table(capsys, monkeypatch):
    ts = "\n".join(str(1700000000 + i * 60) for i in range(8))
    rc = _run(["beacon", "--dest", "x"], stdin=ts, monkeypatch=monkeypatch)
    assert rc == 1  # beacon found → exit 1
    assert "BEACON" in capsys.readouterr().out


def test_beacon_json(capsys, monkeypatch):
    ts = "\n".join(str(1700000000 + i * 60) for i in range(8))
    rc = _run(["beacon", "--format", "json"], stdin=ts, monkeypatch=monkeypatch)
    assert rc == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["verdict"] == "beacon"
    assert doc["mode"] == "beacon"


def test_beacon_gate(capsys, monkeypatch):
    ts = "\n".join(str(1700000000 + i * 60) for i in range(8))
    rc = _run(["beacon", "--fail-on-beacon"], stdin=ts, monkeypatch=monkeypatch)
    assert rc == 2


def test_beacon_irregular_exit_zero(capsys, monkeypatch):
    ts = "not a timestamp\nrandom\n"
    rc = _run(["beacon"], stdin=ts, monkeypatch=monkeypatch)
    assert rc == 0


# ---------------------------------------------------------- correlate analytics
def test_correlate_analytics_flag(capsys, monkeypatch):
    recs = json.dumps([{"host": "a", "jarm": CS}, {"host": "b", "jarm": CS}])
    rc = _run(["correlate", "--format", "json", "--analytics"],
              stdin=recs, monkeypatch=monkeypatch)
    assert rc == 1
    doc = json.loads(capsys.readouterr().out)
    assert "analytics" in doc
    assert doc["analytics"]["campaigns"][0]["hub_host"] in ("a", "b")


def test_correlate_json_no_analytics_by_default(capsys, monkeypatch):
    recs = json.dumps([{"host": "a", "jarm": CS}, {"host": "b", "jarm": CS}])
    rc = _run(["correlate", "--format", "json"], stdin=recs,
              monkeypatch=monkeypatch)
    assert rc == 1
    doc = json.loads(capsys.readouterr().out)
    assert "analytics" not in doc
