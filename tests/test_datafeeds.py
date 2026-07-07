"""Offline coverage for the datafeeds cache / catalog / snapshot layer.

Never hits the network: ``fetch`` is monkeypatched out and ``COGNIS_FEEDS_CACHE``
is pointed at a tmp dir. Exercises catalog loading, cache freshness, the
offline-miss error path, format-aware parsing, and the air-gap snapshot
export/import round-trip.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from c2detect import datafeeds as df


@pytest.fixture
def _tmp_cache(monkeypatch, tmp_path):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))

    def _no_net(*a, **k):
        raise AssertionError("network attempted in offline datafeeds test")

    monkeypatch.setattr(df, "fetch", _no_net)
    return tmp_path


def _seed(cache: Path, feed_id: str, data: bytes, fmt: str, age_hours: float = 0.0):
    (cache / f"{feed_id}.data").write_bytes(data)
    (cache / f"{feed_id}.meta.json").write_text(json.dumps({
        "feed": feed_id, "url": "https://example.test/f",
        "fetched_at": time.time() - age_hours * 3600.0,
        "bytes": len(data), "format": fmt,
    }), encoding="utf-8")


# --------------------------------------------------------------------------- #
# catalog
# --------------------------------------------------------------------------- #
class TestCatalog:
    def test_load_catalog_has_feeds(self):
        cat = df.load_catalog()
        assert isinstance(cat.get("feeds"), list) and cat["feeds"]

    def test_load_catalog_missing_path(self, tmp_path):
        cat = df.load_catalog(str(tmp_path / "nope.json"))
        assert cat == {"feeds": []}

    def test_list_feeds_nonempty(self):
        assert df.list_feeds()

    def test_list_feeds_domain_filter(self):
        ti = df.list_feeds(domain="threat-intel")
        assert all(f.get("domain") == "threat-intel" for f in ti)

    def test_catalog_contains_known_feeds(self):
        ids = {f["id"] for f in df.list_feeds()}
        assert {"feodo-c2", "sslbl"} <= ids


# --------------------------------------------------------------------------- #
# cache freshness
# --------------------------------------------------------------------------- #
class TestCacheFreshness:
    def test_age_none_when_absent(self, _tmp_cache):
        assert df.cached_age_hours("feodo-c2") is None

    def test_age_recent(self, _tmp_cache):
        _seed(_tmp_cache, "feodo-c2", b"[]", "json", age_hours=1.0)
        age = df.cached_age_hours("feodo-c2")
        assert age is not None and 0.5 < age < 1.5

    def test_age_corrupt_meta_returns_none(self, _tmp_cache):
        (_tmp_cache / "feodo-c2.meta.json").write_text("not json", encoding="utf-8")
        assert df.cached_age_hours("feodo-c2") is None

    def test_cache_dir_created(self, monkeypatch, tmp_path):
        target = tmp_path / "nested" / "cache"
        monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(target))
        assert df.cache_dir().is_dir()


# --------------------------------------------------------------------------- #
# get() — offline + format parsing
# --------------------------------------------------------------------------- #
class TestGet:
    def test_offline_missing_raises(self, _tmp_cache):
        with pytest.raises(FileNotFoundError):
            df.get("feodo-c2", offline=True)

    def test_offline_json_parsed(self, _tmp_cache):
        _seed(_tmp_cache, "feodo-c2", b'[{"ip_address": "1.2.3.4"}]', "json")
        data = df.get("feodo-c2", offline=True)
        assert isinstance(data, list) and data[0]["ip_address"] == "1.2.3.4"

    def test_offline_text_kept_as_str(self, _tmp_cache):
        _seed(_tmp_cache, "sslbl", b"some,csv,row", "csv")
        data = df.get("sslbl", offline=True)
        assert isinstance(data, str) and "csv" in data

    def test_update_unknown_feed_raises(self, _tmp_cache):
        with pytest.raises(KeyError):
            df.update("not-a-real-feed")


# --------------------------------------------------------------------------- #
# air-gap snapshot round-trip
# --------------------------------------------------------------------------- #
class TestSnapshot:
    def test_export_then_import_round_trips(self, monkeypatch, tmp_path):
        src = tmp_path / "src"
        monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(src))
        monkeypatch.setattr(df, "fetch", lambda *a, **k: b"x")
        _seed(df.cache_dir(), "feodo-c2", b'[{"ip_address":"9.9.9.9"}]', "json")
        archive = str(tmp_path / "snap.tgz")
        count = df.snapshot_export(archive)
        assert count == 1
        assert Path(archive).is_file()

        # Import into a *different* cache dir; the feed must reappear.
        dst = tmp_path / "dst"
        monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(dst))
        imported = df.snapshot_import(archive)
        assert imported == 1
        data = df.get("feodo-c2", offline=True)
        assert data[0]["ip_address"] == "9.9.9.9"

    def test_export_empty_cache_zero(self, monkeypatch, tmp_path):
        monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "empty"))
        count = df.snapshot_export(str(tmp_path / "snap.tgz"))
        assert count == 0
