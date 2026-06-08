"""Deep tests for C2DETECT. Standard library only, no network."""

from __future__ import annotations

import json
import os
import sys
import unittest
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from c2detect import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    Observation,
    list_signatures,
    observation_from_text,
    scan_observation,
    scan_text,
)
from c2detect.cli import main  # noqa: E402

CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"
MSF_JARM = "07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d"


class TestMetadata(unittest.TestCase):
    def test_names(self):
        self.assertEqual(TOOL_NAME, "c2detect")
        self.assertTrue(TOOL_VERSION)

    def test_db_has_12_plus_families(self):
        rows = list_signatures()
        self.assertGreaterEqual(len(rows), 12)
        # Several well-known families must be present.
        fams = {r["family"] for r in rows}
        for expected in ("Cobalt Strike", "Sliver", "Mythic", "Havoc"):
            self.assertIn(expected, fams)

    def test_every_signature_has_indicators(self):
        for r in list_signatures():
            self.assertTrue(r["indicator_counts"],
                            f"{r['family']} has no indicators")


class TestScoring(unittest.TestCase):
    def test_cobalt_strike_high_confidence(self):
        obs = Observation(
            host="h1", jarm=CS_JARM, port=443,
            uris=["/submit.php", "/__utm.gif"],
            http_banner="Cobalt Strike",
            cert="CN=Major Cobalt Strike serial 146473198",
        )
        res = scan_observation(obs)
        self.assertGreaterEqual(res.count, 1)
        top = res.top
        self.assertEqual(top.family, "Cobalt Strike")
        # Multiple strong indicators -> capped at 100.
        self.assertEqual(top.confidence, 100)
        self.assertEqual(top.severity, "critical")

    def test_corroboration_bonus(self):
        # JARM alone (one strong indicator) vs JARM + cert (two strong).
        one = scan_observation(Observation(jarm=CS_JARM))
        two = scan_observation(
            Observation(jarm=CS_JARM, cert="Major Cobalt Strike"))
        self.assertEqual(one.top.family, "Cobalt Strike")
        self.assertEqual(two.top.family, "Cobalt Strike")
        self.assertGreater(two.top.confidence, one.top.confidence)

    def test_weak_indicator_below_threshold(self):
        # A shared port alone (weight 6) is well under the default threshold.
        res = scan_observation(Observation(port=443))
        self.assertEqual(res.count, 0)

    def test_threshold_floor_surfaces_weak_leads(self):
        res = scan_observation(Observation(port=443), threshold=1)
        self.assertGreater(res.count, 0)

    def test_distinguishes_families(self):
        cs = scan_observation(Observation(jarm=CS_JARM))
        msf = scan_observation(Observation(jarm=MSF_JARM))
        self.assertEqual(cs.top.family, "Cobalt Strike")
        self.assertEqual(msf.top.family, "Metasploit / Meterpreter")

    def test_clean_observation_no_match(self):
        res = scan_observation(Observation(
            host="legit", jarm="0" * 62, port=22, http_banner="OpenSSH_9.6"))
        self.assertEqual(res.count, 0)


class TestTextHarvest(unittest.TestCase):
    def test_extracts_jarm_and_uris_from_blob(self):
        obs = observation_from_text(
            f"connection seen jarm: {CS_JARM} on /submit.php then /pixel.gif")
        self.assertEqual(obs.jarm, CS_JARM)
        self.assertIn("/submit.php", obs.uris)

    def test_scan_text_attributes_cobalt_strike(self):
        res = scan_text(
            f"host: evil.example jarm: {CS_JARM} uri: /submit.php "
            f"banner: Cobalt Strike")
        self.assertEqual(res.top.family, "Cobalt Strike")


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(os.path.dirname(__file__), "_tmp_c2.txt")
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(
                f"host: 198.51.100.77\njarm: {CS_JARM}\nport: 443\n"
                f"uri: /submit.php\nbanner: Cobalt Strike\n"
                f"cert: CN=Major Cobalt Strike serial 146473198\n")

    def tearDown(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def _run(self, argv):
        buf, err = StringIO(), StringIO()
        old_o, old_e = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = buf, err
        try:
            rc = main(argv)
        finally:
            sys.stdout, sys.stderr = old_o, old_e
        return rc, buf.getvalue(), err.getvalue()

    def test_scan_json_nonzero_on_findings(self):
        rc, out, _ = self._run(["scan", "--format", "json", self.path])
        self.assertEqual(rc, 1)
        payload = json.loads(out)
        self.assertEqual(payload["tool"], "c2detect")
        self.assertGreater(payload["match_count"], 0)
        self.assertEqual(payload["matches"][0]["family"], "Cobalt Strike")

    def test_scan_table(self):
        rc, out, _ = self._run(["scan", self.path])
        self.assertEqual(rc, 1)
        self.assertIn("Cobalt Strike", out)

    def test_match_subcommand(self):
        rc, out, _ = self._run([
            "match", "--format", "json", "--jarm", CS_JARM,
            "--uri", "/submit.php", "--cert", "Major Cobalt Strike"])
        self.assertEqual(rc, 1)
        payload = json.loads(out)
        self.assertEqual(payload["matches"][0]["family"], "Cobalt Strike")

    def test_db_subcommand_zero_exit(self):
        rc, out, _ = self._run(["db", "--format", "json"])
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertGreaterEqual(payload["family_count"], 12)

    def test_clean_scan_zero_exit(self):
        clean = os.path.join(os.path.dirname(__file__), "_tmp_clean.txt")
        with open(clean, "w", encoding="utf-8") as fh:
            fh.write("ordinary https session to a CDN, nothing of note")
        try:
            rc, _, _ = self._run(["scan", clean])
            self.assertEqual(rc, 0)
        finally:
            os.remove(clean)

    def test_missing_file_returns_2(self):
        rc, _, _ = self._run(["scan", "no_such_file_98765.txt"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
