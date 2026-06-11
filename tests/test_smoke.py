"""Smoke tests for C2DETECT. Standard library only, no network, no deps."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from c2detect import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    Observation,
    list_signatures,
    scan_observation,
)
from c2detect.cli import main  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(REPO_ROOT, "demos", "01-cobalt-strike-network", "observations.json")
CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"


class TestMetadata(unittest.TestCase):
    def test_version(self):
        self.assertEqual(TOOL_NAME, "c2detect")
        self.assertTrue(TOOL_VERSION)

    def test_db_loaded(self):
        self.assertGreaterEqual(len(list_signatures()), 12)


class TestScanReturnsResult(unittest.TestCase):
    def test_scan_returns_result(self):
        res = scan_observation(Observation(jarm=CS_JARM))
        self.assertGreaterEqual(res.count, 1)
        self.assertEqual(res.top.family, "Cobalt Strike")

    def test_cli_importable(self):
        self.assertTrue(callable(main))


class TestCliEntry(unittest.TestCase):
    def test_demo_scan_via_subprocess(self):
        proc = subprocess.run(
            [sys.executable, "-m", "c2detect", "scan", DEMO, "--format", "json"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        # JSON observation file with a Cobalt Strike JARM => match found, rc=1.
        self.assertEqual(proc.returncode, 1, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["tool"], "c2detect")
        self.assertGreater(data["match_count"], 0)

    def test_version_flag_exit_zero(self):
        proc = subprocess.run(
            [sys.executable, "-m", "c2detect", "--version"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("c2detect", proc.stdout)


if __name__ == "__main__":
    unittest.main()
