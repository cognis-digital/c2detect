"""Tests for the deep-detection + AI/badge/HTML/Action features.

Standard library only, no network. The AI tests NEVER reach a real backend:
the shared backend is off by default and we monkeypatch the LLM call.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from c2detect import (  # noqa: E402
    Observation,
    merge_ai_findings,
    scan_observation,
    to_badge,
    to_html,
)
from c2detect.cli import main  # noqa: E402
from c2detect import ai_backend  # noqa: E402
from c2detect.core import _DB  # noqa: E402

CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"


# --------------------------------------------------------------------------- #
# Deepened native detection
# --------------------------------------------------------------------------- #
class TestDeepDetection(unittest.TestCase):
    def test_db_grew_past_12(self):
        fams = {s.family for s in _DB}
        self.assertGreaterEqual(len(fams), 18)
        for new in ("Caldera (MITRE)", "Pupy RAT", "SILENTTRINITY",
                    "Generic Beaconing Heuristic"):
            self.assertIn(new, fams)

    def test_beacon_cadence_low_jitter_matches_cs(self):
        # 60s fixed cadence + low jitter on 443 == default Beacon shape.
        res = scan_observation(
            Observation(port=443, beacon_interval=60, jitter=0.05),
            threshold=1)
        klasses = {i.klass for m in res.matches for i in m.indicators}
        self.assertIn("beacon", klasses)
        self.assertEqual(res.top.family, "Cobalt Strike")

    def test_high_jitter_does_not_trip_strict_profile(self):
        # 60s but 90% jitter is NOT the default CS shape — no beacon hit for CS.
        res = scan_observation(
            Observation(port=443, beacon_interval=60, jitter=0.90),
            threshold=1)
        cs = [m for m in res.matches if m.family == "Cobalt Strike"]
        if cs:
            self.assertNotIn("beacon", {i.klass for i in cs[0].indicators})

    def test_uri_regex_stager_pattern(self):
        res = scan_observation(Observation(uris=["/aB3x"]), threshold=1)
        klasses = {i.klass for m in res.matches for i in m.indicators}
        self.assertIn("uri_regex", klasses)

    def test_user_agent_indicator(self):
        ua = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"
        res = scan_observation(Observation(user_agent=ua, port=443), threshold=1)
        klasses = {i.klass for m in res.matches for i in m.indicators}
        self.assertIn("user_agent", klasses)

    def test_adaptixc2_branded_header_matches(self):
        # AdaptixC2 ships a branded Server header + default endpoint path.
        res = scan_observation(
            Observation(http_banner="Server: AdaptixC2\nAdaptix-Version: v1.2",
                        port=4321, uris=["/endpoint/login"]),
            threshold=1)
        self.assertEqual(res.top.family, "AdaptixC2")

    def test_adaptixc2_404_body_matches(self):
        res = scan_observation(
            Observation(http_banner="You need to enter the correct connection details.",
                        port=43211),
            threshold=1)
        self.assertIn("AdaptixC2", {m.family for m in res.matches})


# --------------------------------------------------------------------------- #
# Badge + HTML reporters
# --------------------------------------------------------------------------- #
class TestBadge(unittest.TestCase):
    def test_badge_clean(self):
        res = [scan_observation(Observation(jarm="0" * 62))]
        b = to_badge(res)
        self.assertEqual(b["schemaVersion"], 1)
        self.assertEqual(b["message"], "clean")
        self.assertEqual(b["color"], "brightgreen")

    def test_badge_with_findings(self):
        res = [scan_observation(Observation(jarm=CS_JARM))]
        b = to_badge(res)
        self.assertIn("critical", b["message"])
        self.assertEqual(b["color"], "critical")
        # Valid JSON-serializable shields endpoint.
        json.dumps(b)


class TestHtml(unittest.TestCase):
    def test_html_self_contained(self):
        res = [scan_observation(Observation(host="evil.test", jarm=CS_JARM))]
        html = to_html(res)
        self.assertTrue(html.lstrip().startswith("<!doctype html>"))
        self.assertIn("Cobalt Strike", html)
        self.assertIn("evil.test", html)
        # No external asset references (self-contained).
        self.assertNotIn("http://", html.split("cognis-digital/c2detect")[0])

    def test_html_clean(self):
        res = [scan_observation(Observation(jarm="0" * 62))]
        html = to_html(res)
        self.assertIn("No C2 indicators", html)


# --------------------------------------------------------------------------- #
# AI merge / dedupe (no network)
# --------------------------------------------------------------------------- #
class TestAiMerge(unittest.TestCase):
    def test_dedupe_against_rule_family(self):
        res = scan_observation(Observation(jarm=CS_JARM))  # Cobalt Strike
        ai = [
            {"title": "Cobalt Strike beacon staging URI", "evidence": "/submit.php",
             "severity": "high", "novel": False},  # duplicate -> dropped
            {"title": "Hardcoded staging key in config", "evidence": "key=abcd",
             "severity": "medium", "novel": True},  # novel -> kept
        ]
        kept = merge_ai_findings(res, ai)
        titles = [f["title"] for f in kept]
        self.assertEqual(len(kept), 1)
        self.assertIn("Hardcoded staging key in config", titles)
        self.assertEqual(kept[0]["source"], "ai")
        self.assertTrue(kept[0]["candidate_novel"])

    def test_dedupe_identical_ai_findings(self):
        res = scan_observation(Observation(jarm="0" * 62))  # no rule match
        ai = [
            {"title": "Same", "evidence": "x", "severity": "low"},
            {"title": "Same", "evidence": "x", "severity": "low"},
        ]
        self.assertEqual(len(merge_ai_findings(res, ai)), 1)


# --------------------------------------------------------------------------- #
# AI backend is OFF by default and degrades gracefully
# --------------------------------------------------------------------------- #
class TestAiBackendOffByDefault(unittest.TestCase):
    def setUp(self):
        # Strip any ambient COGNIS_AI_* so the default really is off.
        self._saved = {k: os.environ.pop(k, None)
                       for k in ("COGNIS_AI_BACKEND", "COGNIS_AI_ENDPOINT",
                                 "COGNIS_AI_MODEL", "COGNIS_AI_KEY")}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is not None:
                os.environ[k] = v

    def test_disabled_returns_empty(self):
        b = ai_backend.CognisAIBackend()
        self.assertFalse(b.is_enabled())
        self.assertEqual(b.analyze_code("anything"), [])

    def test_unreachable_backend_never_raises(self):
        b = ai_backend.CognisAIBackend(
            endpoint="http://127.0.0.1:59998/v1", model="x")
        self.assertTrue(b.is_enabled())
        self.assertFalse(b.health())          # nothing listening
        self.assertEqual(b.analyze_code("code"), [])  # graceful empty


# --------------------------------------------------------------------------- #
# CLI: --ai is off by default; --ai with backend DOWN still succeeds on rules
# --------------------------------------------------------------------------- #
class TestCliAiAndFormats(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(os.path.dirname(__file__), "_tmp_ai.txt")
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(f"host: 198.51.100.9\njarm: {CS_JARM}\n"
                     f"uri: /submit.php\nbanner: Cobalt Strike\n")

    def tearDown(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def _run(self, argv, env=None):
        buf, err = StringIO(), StringIO()
        old_o, old_e = sys.stdout, sys.stderr
        saved = {}
        if env:
            for k, v in env.items():
                saved[k] = os.environ.get(k)
                os.environ[k] = v
        sys.stdout, sys.stderr = buf, err
        try:
            rc = main(argv)
        finally:
            sys.stdout, sys.stderr = old_o, old_e
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        return rc, buf.getvalue(), err.getvalue()

    def test_without_ai_is_deterministic(self):
        _, out1, _ = self._run(["scan", "--format", "json", self.path])
        _, out2, _ = self._run(["scan", "--format", "json", self.path])
        self.assertEqual(out1, out2)
        self.assertNotIn("ai_findings", out1)

    def test_ai_no_backend_configured_falls_back(self):
        # No COGNIS_AI_* set -> note + rule findings, never crash.
        for k in ("COGNIS_AI_BACKEND", "COGNIS_AI_ENDPOINT", "COGNIS_AI_MODEL"):
            os.environ.pop(k, None)
        rc, out, err = self._run(["scan", "--format", "json", "--ai", self.path])
        self.assertEqual(rc, 1)
        payload = json.loads(out)
        self.assertGreater(payload["match_count"], 0)
        self.assertIn("note:", err)

    def test_ai_backend_down_falls_back_to_rules(self):
        rc, out, err = self._run(
            ["scan", "--format", "json", "--ai", self.path],
            env={"COGNIS_AI_BACKEND": "uncensored-fleet",
                 "COGNIS_AI_ENDPOINT": "http://127.0.0.1:59997/v1",
                 "COGNIS_AI_MODEL": "x"})
        self.assertEqual(rc, 1)
        payload = json.loads(out)
        self.assertGreater(payload["match_count"], 0)
        self.assertIn("unreachable", err)

    def test_format_badge(self):
        rc, out, _ = self._run(["scan", "--format", "badge", self.path])
        b = json.loads(out)
        self.assertEqual(b["schemaVersion"], 1)
        self.assertEqual(rc, 1)

    def test_format_html(self):
        rc, out, _ = self._run(["scan", "--format", "html", self.path])
        self.assertIn("<!doctype html>", out)
        self.assertIn("Cobalt Strike", out)
        self.assertEqual(rc, 1)

    def test_match_behavioral_flags(self):
        rc, out, _ = self._run([
            "match", "--format", "json", "--threshold", "1",
            "--port", "443", "--beacon-interval", "60", "--jitter", "0.05"])
        payload = json.loads(out)
        klasses = {i["class"] for i in payload["matches"][0]["indicators"]}
        self.assertIn("beacon", klasses)


if __name__ == "__main__":
    unittest.main()
