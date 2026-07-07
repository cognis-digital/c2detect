"""CLI error-path and exit-code coverage.

The CLI is the contract most users hit. These tests pin its behaviour on the
unhappy paths: missing files, bad output destinations, unknown feeds, empty
input, and the exit-code gate (0 clean / 1 finding / 2 hard-fail). They call
``c2detect.cli.main`` in-process and assert the returned exit code + stderr,
so they run fully offline with no subprocess overhead.
"""

from __future__ import annotations

import json

import pytest

from c2detect.cli import main

CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"


# --------------------------------------------------------------------------- #
# scan / correlate — missing inputs
# --------------------------------------------------------------------------- #
class TestMissingInputs:
    def test_scan_missing_file_rc2(self, capsys):
        rc = main(["scan", "no-such-file.json"])
        assert rc == 2
        assert "error" in capsys.readouterr().err.lower()

    def test_correlate_missing_file_rc2(self, capsys):
        rc = main(["correlate", "no-such-file.json"])
        assert rc == 2
        assert "no such file" in capsys.readouterr().err.lower()

    def test_scan_missing_dir_member_ok(self, tmp_path, capsys):
        # An empty directory yields no blobs -> a single empty observation, rc 0.
        d = tmp_path / "empty"
        d.mkdir()
        rc = main(["scan", str(d)])
        assert rc == 0


# --------------------------------------------------------------------------- #
# rules — bad output destination (the bug this fix closes)
# --------------------------------------------------------------------------- #
class TestRulesOutput:
    def test_rules_to_unwritable_path_rc2(self, capsys):
        rc = main(["rules", "--format", "sigma", "-o",
                   "/no-such-dir-xyz/out.yml"])
        assert rc == 2
        err = capsys.readouterr().err.lower()
        assert "cannot write" in err or "error" in err

    def test_rules_to_valid_path_rc0(self, tmp_path, capsys):
        out = tmp_path / "c2.sigma.yml"
        rc = main(["rules", "--format", "sigma", "-o", str(out)])
        assert rc == 0
        assert out.read_text(encoding="utf-8").startswith("title:")

    def test_rules_suricata_to_stdout(self, capsys):
        rc = main(["rules", "--format", "suricata"])
        assert rc == 0
        assert "alert " in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# feeds — unknown feed id
# --------------------------------------------------------------------------- #
class TestFeedsErrors:
    def test_feeds_get_unknown_rc1(self, capsys):
        rc = main(["feeds", "get", "not-a-feed"])
        assert rc == 1
        assert "not a c2detect feed" in capsys.readouterr().err.lower()

    def test_feeds_no_subcommand_rc2(self, capsys):
        rc = main(["feeds"])
        assert rc == 2


# --------------------------------------------------------------------------- #
# exit-code contract
# --------------------------------------------------------------------------- #
class TestExitCodes:
    def _write(self, tmp_path, name, payload):
        p = tmp_path / name
        p.write_text(json.dumps(payload), encoding="utf-8")
        return str(p)

    def test_clean_scan_rc0(self, tmp_path):
        f = self._write(tmp_path, "clean.json", [{"host": "x", "port": 12345}])
        assert main(["scan", f, "--format", "json"]) == 0

    def test_match_found_rc1(self, tmp_path):
        f = self._write(tmp_path, "cs.json", [{"jarm": CS_JARM}])
        assert main(["scan", f, "--format", "json"]) == 1

    def test_fail_on_critical_rc2(self, tmp_path):
        f = self._write(tmp_path, "cs.json", [{"jarm": CS_JARM}])
        assert main(["scan", f, "--fail-on", "critical", "--format", "json"]) == 2

    def test_fail_on_critical_clean_rc0(self, tmp_path):
        f = self._write(tmp_path, "clean.json", [{"host": "x", "port": 12345}])
        assert main(["scan", f, "--fail-on", "critical", "--format", "json"]) == 0

    def test_match_subcommand_jarm_rc1(self):
        assert main(["match", "--jarm", CS_JARM, "--format", "json"]) == 1

    def test_match_subcommand_clean_rc0(self):
        assert main(["match", "--port", "12345", "--format", "json"]) == 0

    def test_correlate_no_campaign_rc0(self, tmp_path):
        f = self._write(tmp_path, "lone.json", [{"jarm": CS_JARM}])
        assert main(["correlate", f]) == 0

    def test_self_check_healthy_rc0(self, capsys):
        assert main(["self-check"]) == 0


# --------------------------------------------------------------------------- #
# output formats round-trip
# --------------------------------------------------------------------------- #
class TestOutputFormats:
    def test_match_json_valid(self, capsys):
        main(["match", "--jarm", CS_JARM, "--format", "json"])
        data = json.loads(capsys.readouterr().out)
        assert data["tool"] == "c2detect"
        assert data["match_count"] >= 1

    def test_match_sarif_valid(self, capsys):
        main(["match", "--jarm", CS_JARM, "--format", "sarif"])
        data = json.loads(capsys.readouterr().out)
        assert data["version"] == "2.1.0"

    def test_match_badge_valid(self, capsys):
        main(["match", "--jarm", CS_JARM, "--format", "badge"])
        data = json.loads(capsys.readouterr().out)
        assert data["schemaVersion"] == 1

    def test_match_html_self_contained(self, capsys):
        main(["match", "--jarm", CS_JARM, "--format", "html"])
        out = capsys.readouterr().out
        assert "<!doctype html>" in out.lower()

    def test_db_json_lists_families(self, capsys):
        main(["db", "--format", "json"])
        data = json.loads(capsys.readouterr().out)
        assert data["family_count"] >= 12

    def test_db_table_renders(self, capsys):
        rc = main(["db"])
        assert rc == 0
        assert "FAMILY" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# no-command / help
# --------------------------------------------------------------------------- #
class TestNoCommand:
    def test_no_command_prints_help_rc2(self, capsys):
        rc = main([])
        assert rc == 2

    def test_probe_without_authorized_refused_rc2(self, capsys):
        rc = main(["probe", "example.com"])
        assert rc == 2
        assert "authorized" in capsys.readouterr().err.lower()

    def test_probe_authorized_without_allowlist_rc2(self, capsys):
        rc = main(["probe", "example.com", "--authorized"])
        assert rc == 2
        assert "allowlist" in capsys.readouterr().err.lower()
