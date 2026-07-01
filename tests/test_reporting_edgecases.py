"""Edge-case coverage for reporters (SARIF / HTML / badge), feed enrichment,
and the AI-merge dedup logic.

All offline. Feed tests point ``COGNIS_FEEDS_CACHE`` at the bundled trimmed
fixtures and forbid the network, mirroring tests/test_feeds.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from c2detect.core import (
    Observation,
    merge_ai_findings,
    scan_observation,
    scan_observations,
    to_badge,
    to_html,
    to_sarif,
)

CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"
FIXTURE_CACHE = Path(__file__).resolve().parent / "fixtures" / "feeds_cache"


# --------------------------------------------------------------------------- #
# SARIF reporter
# --------------------------------------------------------------------------- #
class TestSarif:
    def test_rule_id_sanitized(self):
        res = scan_observations([{"jarm": CS_JARM}])
        sarif = to_sarif(res)
        rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
        assert all(rid.startswith("C2-") for rid in rule_ids)
        # No spaces / punctuation survive into the rule id.
        assert all(c.isalnum() or c == "-" for rid in rule_ids for c in rid)

    def test_one_rule_per_family(self):
        # Two CS hosts -> still one CS rule, two results.
        res = scan_observations([{"jarm": CS_JARM}, {"jarm": CS_JARM}])
        sarif = to_sarif(res)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        results = sarif["runs"][0]["results"]
        assert len(rules) == 1
        assert len(results) == 2

    def test_unnamed_host_placeholder(self):
        res = scan_observations([{"jarm": CS_JARM}])  # no host field
        sarif = to_sarif(res)
        loc = sarif["runs"][0]["results"][0]["locations"][0]
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "(unnamed-host)"

    def test_every_result_references_declared_rule(self):
        recs = [{"host": "a", "jarm": CS_JARM},
                {"host": "b", "ja4": "t13d190900_9dc949149365_97f8aa674fd9"}]
        sarif = to_sarif(scan_observations(recs))
        declared = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        referenced = {r["ruleId"] for r in sarif["runs"][0]["results"]}
        assert referenced <= declared

    def test_confidence_in_properties(self):
        sarif = to_sarif(scan_observations([{"jarm": CS_JARM}]))
        props = sarif["runs"][0]["results"][0]["properties"]
        assert "confidence" in props and isinstance(props["confidence"], int)

    def test_serializable(self):
        sarif = to_sarif(scan_observations([{"jarm": CS_JARM}]))
        assert json.loads(json.dumps(sarif))["version"] == "2.1.0"


# --------------------------------------------------------------------------- #
# HTML reporter
# --------------------------------------------------------------------------- #
class TestHtml:
    def test_self_contained_no_remote_assets(self):
        html = to_html(scan_observations([{"host": "h", "jarm": CS_JARM}]))
        # No external stylesheet/script/image/font requests.
        assert "src=\"http" not in html
        assert "@import" not in html
        assert ".css\"" not in html

    def test_clean_message_when_empty(self):
        assert "No C2 indicators found" in to_html([])

    def test_flagged_host_appears(self):
        html = to_html(scan_observations([{"host": "1.2.3.4", "jarm": CS_JARM}]))
        assert "1.2.3.4" in html

    def test_html_escapes_angle_brackets(self):
        html = to_html(scan_observations([{"host": "<script>", "jarm": CS_JARM}]))
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_summary_counts_present(self):
        html = to_html(scan_observations([{"jarm": CS_JARM}]))
        assert "observations" in html and "rule findings" in html


# --------------------------------------------------------------------------- #
# Badge reporter
# --------------------------------------------------------------------------- #
class TestBadge:
    def test_clean(self):
        b = to_badge([])
        assert b["message"] == "clean" and b["color"] == "brightgreen"

    def test_critical_color(self):
        b = to_badge(scan_observations([{"jarm": CS_JARM}]))
        assert "critical" in b["message"] and b["color"] == "critical"

    def test_singular_vs_plural(self):
        one = to_badge(scan_observations([{"jarm": CS_JARM}]))
        assert "1 finding " in one["message"] or "1 finding" in one["message"]

    def test_schema_version(self):
        assert to_badge([])["schemaVersion"] == 1


# --------------------------------------------------------------------------- #
# AI-finding merge dedup
# --------------------------------------------------------------------------- #
class TestAiMerge:
    def test_drops_finding_naming_existing_family(self):
        res = scan_observation(Observation(jarm=CS_JARM))
        kept = merge_ai_findings(
            res, [{"title": "Cobalt Strike beacon seen", "evidence": "x"}])
        assert kept == []

    def test_keeps_novel_finding(self):
        res = scan_observation(Observation(jarm=CS_JARM))
        kept = merge_ai_findings(
            res, [{"title": "Unusual DNS tunneling", "evidence": "many TXT"}])
        assert len(kept) == 1
        assert kept[0]["source"] == "ai"

    def test_dedups_identical_ai_findings(self):
        res = scan_observation(Observation())
        f = {"title": "Suspicious", "evidence": "same"}
        kept = merge_ai_findings(res, [f, dict(f)])
        assert len(kept) == 1

    def test_ignores_non_dict_entries(self):
        res = scan_observation(Observation())
        kept = merge_ai_findings(res, ["not a dict", 42, None])
        assert kept == []

    def test_severity_normalized(self):
        res = scan_observation(Observation())
        kept = merge_ai_findings(
            res, [{"title": "x", "evidence": "y", "severity": "BOGUS"}])
        assert kept[0]["severity"] == "info"

    def test_novel_flag_propagated(self):
        res = scan_observation(Observation())
        kept = merge_ai_findings(
            res, [{"title": "x", "evidence": "y", "novel": True}])
        assert kept[0]["candidate_novel"] is True


# --------------------------------------------------------------------------- #
# Feed enrichment (offline, fixture cache)
# --------------------------------------------------------------------------- #
@pytest.fixture
def _offline_feeds(monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(FIXTURE_CACHE))
    import c2detect.datafeeds as df

    def _no_net(*a, **k):
        raise AssertionError("network attempted in offline feed test")

    monkeypatch.setattr(df, "fetch", _no_net)
    yield


class TestFeedEnrichment:
    def test_known_c2_ip_flagged(self, _offline_feeds):
        from c2detect import feeds
        feodo = feeds.feodo_c2_ips(offline=True)
        ja3bl = feeds.sslbl_ja3(offline=True)
        obs = Observation(host="185.220.101.45")
        hits = feeds.enrich_observation(obs, feodo=feodo, ja3bl=ja3bl)
        assert any(h["source"] == "feodo-c2" for h in hits)
        assert all(h["severity"] == "critical" for h in hits)

    def test_clean_ip_no_hit(self, _offline_feeds):
        from c2detect import feeds
        feodo = feeds.feodo_c2_ips(offline=True)
        ja3bl = feeds.sslbl_ja3(offline=True)
        obs = Observation(host="8.8.8.8")
        assert feeds.enrich_observation(obs, feodo=feodo, ja3bl=ja3bl) == []

    def test_offline_missing_cache_raises(self, monkeypatch, tmp_path):
        monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
        import c2detect.datafeeds as df
        monkeypatch.setattr(
            df, "fetch",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("no net")))
        from c2detect import feeds
        with pytest.raises(FileNotFoundError):
            feeds.sslbl_ja3(offline=True)

    def test_only_relevant_feeds_exposed(self, _offline_feeds):
        from c2detect import feeds
        assert set(feeds.RELEVANT_FEEDS) == {"feodo-c2", "sslbl"}

    def test_unknown_feed_id_rejected(self, _offline_feeds):
        from c2detect import feeds
        with pytest.raises(KeyError):
            feeds._require_relevant("not-a-feed")

    def test_enrich_observations_batch(self, _offline_feeds):
        from c2detect import feeds
        obs = [Observation(host="185.220.101.45"), Observation(host="8.8.8.8")]
        out = feeds.enrich_observations(obs, offline=True)
        # Only the known-bad host (index 0) yields hits.
        assert 0 in out and 1 not in out
