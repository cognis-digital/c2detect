"""Shared helpers for the c2detect demo scenarios.

Every scenario in this directory runs **fully offline** against the real
c2detect engine and the bundled telemetry fixtures under ``demos/NN-*/``. No
network calls, no fabricated output — each demo loads a real observation file,
runs it through the public API (``scan_observations`` / ``correlate`` /
``enrich_observations`` / ``rules``), and narrates the result.
"""
from __future__ import annotations

import json
import os
import sys

# allow `python demos/NN_name.py` from anywhere
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS_DIR = os.path.join(REPO_ROOT, "demos")

# The pre-seeded air-gap feed snapshot bundled with demo 13. Pointing the feeds
# cache here lets the threat-intel demo run with zero network access.
FEEDS_SNAPSHOT = os.path.join(DEMOS_DIR, "13-threat-intel-feeds")


def scenario(path: str) -> str:
    """Absolute path to a bundled scenario file, e.g. ``04-sliver-mtls/observations.json``."""
    return os.path.join(DEMOS_DIR, path)


def load_observations(path: str) -> list[dict]:
    """Load a bundled scenario's JSON observation records (a list of dicts)."""
    with open(scenario(path), "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        for key in ("observations", "records", "hosts"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    return data


def rule(title: str) -> None:
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72)


def sev_tag(severity: str) -> str:
    """A fixed-width, uppercased severity tag for aligned console output."""
    return f"[{severity.upper():<8}]"
