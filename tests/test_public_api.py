"""Pin the public API surface so a refactor cannot silently drop an export.

These are the names downstream code (and the README examples) import from the
top-level ``c2detect`` package. If one disappears or changes shape, this fails
loudly. Pure import-and-shape checks; no network.
"""

from __future__ import annotations

import inspect

import c2detect

CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"

CORE_CALLABLES = [
    "scan_observation", "scan_observations", "scan_text",
    "observation_from_record", "observation_from_text",
    "list_signatures", "signatures", "load_records",
    "to_badge", "to_html", "to_sarif", "worst_severity",
    "fails_gate", "fails_gate_with_ai", "merge_ai_findings",
]
RULE_CALLABLES = ["to_sigma", "to_suricata", "generate"]
CORR_CALLABLES = ["correlate", "correlate_observations"]
ACTIVE_CALLABLES = ["probe_target", "probe_targets", "jarm_like"]
DATACLASSES = ["Observation", "Signature", "Match", "MatchedIndicator",
               "ScanResult", "ProbeResult", "Campaign", "HostNode",
               "SharedPivot", "Scope", "RateLimiter"]


import pytest


@pytest.mark.parametrize("name", CORE_CALLABLES + RULE_CALLABLES
                         + CORR_CALLABLES + ACTIVE_CALLABLES)
def test_callable_exported(name):
    assert hasattr(c2detect, name), f"missing export: {name}"
    assert callable(getattr(c2detect, name))


@pytest.mark.parametrize("name", DATACLASSES)
def test_class_exported(name):
    assert hasattr(c2detect, name)
    assert inspect.isclass(getattr(c2detect, name))


@pytest.mark.parametrize("name", ["DEFAULT_THRESHOLD", "SEVERITY_ORDER",
                                  "PIVOT_WEIGHTS", "TOOL_NAME", "TOOL_VERSION",
                                  "AUTHORIZED_USE_BANNER"])
def test_constant_exported(name):
    assert hasattr(c2detect, name)


class TestVersionAndMetadata:
    def test_tool_name(self):
        assert c2detect.TOOL_NAME == "c2detect"

    def test_version_is_semverish(self):
        parts = c2detect.TOOL_VERSION.split(".")
        assert len(parts) >= 2 and all(p.isdigit() for p in parts[:2])

    def test_default_threshold_in_range(self):
        assert 0 < c2detect.DEFAULT_THRESHOLD < 100

    def test_severity_order_complete(self):
        assert set(c2detect.SEVERITY_ORDER) == {
            "critical", "high", "medium", "low", "info"}

    def test_db_has_minimum_families(self):
        assert len(c2detect.signatures()) >= 12


class TestEndToEndViaPublicApi:
    def test_scan_to_sarif(self):
        res = c2detect.scan_observations([{"jarm": CS_JARM}])
        sarif = c2detect.to_sarif(res)
        assert sarif["version"] == "2.1.0"

    def test_scan_to_badge(self):
        res = c2detect.scan_observations([{"jarm": CS_JARM}])
        assert c2detect.to_badge(res)["color"] == "critical"

    def test_correlate_via_public_api(self):
        res = c2detect.scan_observations([{"host": "a", "jarm": CS_JARM},
                                          {"host": "b", "jarm": CS_JARM}])
        camps = c2detect.correlate(res)
        assert len(camps) == 1

    def test_rules_via_public_api(self):
        assert c2detect.to_sigma().startswith("title:")
        assert "alert " in c2detect.to_suricata()
