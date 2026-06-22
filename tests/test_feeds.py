"""Offline tests for the live threat-intel feed layer.

These tests NEVER hit the network: ``COGNIS_FEEDS_CACHE`` is pointed at the
trimmed fixtures under ``tests/fixtures/feeds_cache`` and every feed access uses
``offline=True`` (or the CLI ``--offline`` flag). They prove the air-gap path:
c2detect enriches observations purely from a cached snapshot.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

FIXTURE_CACHE = Path(__file__).resolve().parent / "fixtures" / "feeds_cache"


@pytest.fixture(autouse=True)
def _point_cache_at_fixtures(monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(FIXTURE_CACHE))
    # Belt + braces: make any accidental network call explode loudly.
    import c2detect.datafeeds as df

    def _no_net(*a, **k):  # pragma: no cover - guard
        raise AssertionError("network access attempted in an offline test")

    monkeypatch.setattr(df, "fetch", _no_net)
    yield


# --------------------------------------------------------------------------- #
# catalog filtering
# --------------------------------------------------------------------------- #
def test_only_relevant_feeds_exposed():
    from c2detect import feeds

    assert feeds.RELEVANT_FEEDS == ("feodo-c2", "sslbl")
    ids = {f["id"] for f in feeds.catalog()["feeds"]}
    assert ids == {"feodo-c2", "sslbl"}
    # The full catalog has many more feeds; c2detect must not surface them.
    full_ids = {f["id"] for f in feeds.datafeeds.load_catalog()["feeds"]}
    assert "cisa-kev" in full_ids and "cisa-kev" not in ids


# --------------------------------------------------------------------------- #
# parsing the cached fixtures (offline)
# --------------------------------------------------------------------------- #
def test_feodo_ips_parsed_offline():
    from c2detect import feeds

    table = feeds.feodo_c2_ips(offline=True)
    assert "185.220.101.45" in table
    assert table["185.220.101.45"]["malware"] == "Emotet"
    assert len(table) >= 3


def test_sslbl_ja3_parsed_offline():
    from c2detect import feeds

    table = feeds.sslbl_ja3(offline=True)
    assert "a0e9f5d64349fb13191bc781f81f42e1" in table
    assert table["a0e9f5d64349fb13191bc781f81f42e1"]["reason"] == "Cobalt Strike"
    # Comment / header lines must be skipped.
    assert all(len(k) == 32 for k in table)


def test_offline_missing_cache_raises(monkeypatch, tmp_path):
    from c2detect import feeds

    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    with pytest.raises(FileNotFoundError):
        feeds.sslbl_ja3(offline=True)


# --------------------------------------------------------------------------- #
# the real enrichment
# --------------------------------------------------------------------------- #
def test_enrich_flags_known_c2_ip():
    from c2detect import feeds
    from c2detect.core import Observation

    feodo = feeds.feodo_c2_ips(offline=True)
    ja3bl = feeds.sslbl_ja3(offline=True)

    obs = Observation(host="45.142.212.61")
    hits = feeds.enrich_observation(obs, feodo=feodo, ja3bl=ja3bl)
    assert len(hits) == 1
    h = hits[0]
    assert h["source"] == "feodo-c2"
    assert h["severity"] == "critical"
    assert h["malware"] == "Dridex"


def test_enrich_flags_known_bad_ja3():
    from c2detect import feeds
    from c2detect.core import Observation

    feodo = feeds.feodo_c2_ips(offline=True)
    ja3bl = feeds.sslbl_ja3(offline=True)

    obs = Observation(host="10.0.0.5",
                      ja3="72a589da586844d7f0818ce684948eea")
    hits = feeds.enrich_observation(obs, feodo=feodo, ja3bl=ja3bl)
    assert len(hits) == 1
    assert hits[0]["source"] == "sslbl"
    assert hits[0]["malware"] == "TrickBot"


def test_enrich_clean_observation_no_hits():
    from c2detect import feeds
    from c2detect.core import Observation

    feodo = feeds.feodo_c2_ips(offline=True)
    ja3bl = feeds.sslbl_ja3(offline=True)
    obs = Observation(host="8.8.8.8", ja3="deadbeefdeadbeefdeadbeefdeadbeef")
    assert feeds.enrich_observation(obs, feodo=feodo, ja3bl=ja3bl) == []


def test_enrich_both_ip_and_ja3():
    from c2detect import feeds
    from c2detect.core import Observation

    feodo = feeds.feodo_c2_ips(offline=True)
    ja3bl = feeds.sslbl_ja3(offline=True)
    obs = Observation(host="185.220.101.45",
                      ja3="e7d705a3286e19ea42f587b344ee6865")
    hits = feeds.enrich_observation(obs, feodo=feodo, ja3bl=ja3bl)
    assert {h["source"] for h in hits} == {"feodo-c2", "sslbl"}


# --------------------------------------------------------------------------- #
# CLI wiring (offline)
# --------------------------------------------------------------------------- #
def test_cli_feeds_list(capsys):
    from c2detect.cli import main

    rc = main(["feeds", "list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "feodo-c2" in out and "sslbl" in out
    # Catalog filtering: an unrelated feed must not appear.
    assert "cisa-kev" not in out


def test_cli_feeds_get_offline(capsys):
    from c2detect.cli import main

    rc = main(["feeds", "get", "feodo-c2", "--offline"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "185.220.101.45" in out


def test_cli_scan_with_feeds_offline_flags_c2(tmp_path, capsys):
    from c2detect.cli import main

    obs_file = tmp_path / "obs.json"
    obs_file.write_text(json.dumps([
        {"host": "45.142.212.61", "ja3": "72a589da586844d7f0818ce684948eea"},
        {"host": "192.0.2.10"},
    ]))
    rc = main(["scan", str(obs_file), "--feeds", "--offline", "--format", "json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["feed_finding_count"] == 2
    sources = {f["source"] for f in payload["feed_findings"]}
    assert sources == {"feodo-c2", "sslbl"}
    # scan exits non-zero when any indicator (incl. a feed hit) is present.
    assert rc != 0


def test_cli_match_feeds_failon_gate_offline():
    from c2detect.cli import main

    # A known-C2 IP with no fingerprint should still trip --fail-on critical
    # purely on the live-feed hit.
    rc = main(["match", "--host", "45.142.212.61",
               "--feeds", "--offline", "--fail-on", "critical",
               "--format", "json"])
    assert rc == 2
