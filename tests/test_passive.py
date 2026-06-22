"""Tests for c2detect PASSIVE mode — the safe, network-free default.

Covers JSONL/NDJSON ingest, free-text extraction, field aliasing, and the
multi-observation scan pipeline. All offline.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from c2detect.core import (  # noqa: E402
    Observation,
    load_records,
    observation_from_record,
    observation_from_text,
    scan_observation,
    scan_observations,
    scan_text,
)
from c2detect.cli import main  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"


class TestJsonlIngest(unittest.TestCase):
    def test_jsonl_two_records(self):
        text = (
            '{"host":"a","jarm":"%s"}\n'
            '{"host":"b","port":50050}\n' % CS_JARM
        )
        recs = load_records(text)
        self.assertIsNotNone(recs)
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[0]["host"], "a")

    def test_jsonl_blank_lines_ignored(self):
        text = '{"host":"a"}\n\n   \n{"host":"b"}\n'
        recs = load_records(text)
        self.assertEqual(len(recs), 2)

    def test_jsonl_with_garbage_line_below_majority_returns_none(self):
        # one good object, several junk lines that start with '{' won't parse
        text = '{"host":"a"}\n{bad\n{worse\n{nope\n'
        recs = load_records(text)
        # only 1 of 4 lines parse => below half => None (fall back to text)
        self.assertIsNone(recs)

    def test_standard_json_array_still_works(self):
        recs = load_records('[{"host":"a"},{"host":"b"}]')
        self.assertEqual(len(recs), 2)

    def test_wrapped_observations_key(self):
        recs = load_records('{"observations":[{"host":"x"}]}')
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["host"], "x")

    def test_non_json_returns_none(self):
        self.assertIsNone(load_records("just some log text\nno json here"))

    def test_empty_returns_none(self):
        self.assertIsNone(load_records(""))
        self.assertIsNone(load_records("   \n  "))

    def test_jsonl_pipeline_scan_via_cli(self):
        text = (
            '{"host":"evil1","jarm":"%s"}\n'
            '{"host":"clean","port":443}\n' % CS_JARM
        )
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False,
                                         encoding="utf-8") as fh:
            fh.write(text)
            path = fh.name
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "c2detect", "scan", path, "--format", "json"],
                cwd=REPO_ROOT, capture_output=True, text=True,
            )
            data = json.loads(proc.stdout)
            self.assertEqual(data["result_count"], 2)
            self.assertGreater(data["match_count"], 0)
        finally:
            os.unlink(path)


class TestTextExtraction(unittest.TestCase):
    def test_extract_jarm_keyvalue(self):
        obs = observation_from_text("jarm: %s" % CS_JARM)
        self.assertEqual(obs.jarm, CS_JARM)

    def test_extract_free_floating_jarm(self):
        obs = observation_from_text("saw fingerprint %s on the wire" % CS_JARM)
        self.assertEqual(obs.jarm, CS_JARM)

    def test_extract_port_and_uri(self):
        obs = observation_from_text("port: 50050  uri: /submit.php")
        self.assertEqual(obs.port, 50050)
        self.assertIn("/submit.php", obs.uris)

    def test_beacon_and_jitter(self):
        obs = observation_from_text("beacon_interval: 60  jitter: 10")
        self.assertEqual(obs.beacon_interval, 60.0)
        self.assertAlmostEqual(obs.jitter, 0.10)

    def test_text_scan_detects_cs(self):
        res = scan_text("jarm=%s" % CS_JARM)
        self.assertGreaterEqual(res.count, 1)
        self.assertEqual(res.top.family, "Cobalt Strike")


class TestFieldAliasing(unittest.TestCase):
    def test_dest_ip_alias(self):
        obs = observation_from_record({"dest_ip": "1.2.3.4", "jarm": CS_JARM})
        self.assertEqual(obs.host, "1.2.3.4")

    def test_dst_port_alias(self):
        obs = observation_from_record({"dst_port": "50050"})
        self.assertEqual(obs.port, 50050)

    def test_uri_singular_alias(self):
        obs = observation_from_record({"uri": "/beacon"})
        self.assertIn("/beacon", obs.uris)

    def test_sleep_alias_to_beacon(self):
        obs = observation_from_record({"sleep": 30})
        self.assertEqual(obs.beacon_interval, 30.0)

    def test_jitter_percent_normalized(self):
        obs = observation_from_record({"jitter": 25})
        self.assertAlmostEqual(obs.jitter, 0.25)


class TestMultiObservationScan(unittest.TestCase):
    def test_scan_observations_batch(self):
        recs = [{"jarm": CS_JARM}, {"port": 443}]
        results = scan_observations(recs)
        self.assertEqual(len(results), 2)
        self.assertGreaterEqual(results[0].count, 1)

    def test_clean_observation_no_match(self):
        res = scan_observation(Observation(host="benign", port=443))
        self.assertEqual(res.count, 0)


if __name__ == "__main__":
    unittest.main()
