"""Tests for MISP + STIX 2.1 export.

Offline, deterministic. Validates event/bundle structure, indicator patterning,
kill-chain phases, dedupe, and reproducible IDs.
"""
from __future__ import annotations

import re

import pytest

from c2detect.core import scan_observations, signatures
from c2detect.export import to_misp, to_stix, signatures_to_stix, _uuid5

CS = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"


@pytest.fixture
def results():
    return scan_observations([
        {"host": "1.2.3.4", "jarm": CS, "uris": ["/submit.php"],
         "user_agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"},
        {"host": "evil.example.com", "jarm": CS},
    ])


# --------------------------------------------------------------------------- MISP
class TestMISP:
    def test_event_shape(self, results):
        doc = to_misp(results)
        assert "Event" in doc
        ev = doc["Event"]
        assert ev["info"]
        assert re.match(r"^[0-9a-f-]{36}$", ev["uuid"])
        assert isinstance(ev["Attribute"], list) and ev["Attribute"]
        assert isinstance(ev["Tag"], list) and ev["Tag"]

    def test_ip_host_becomes_ip_dst(self, results):
        doc = to_misp(results)
        types = {a["type"] for a in doc["Event"]["Attribute"]}
        assert "ip-dst" in types      # 1.2.3.4
        assert "hostname" in types    # evil.example.com

    def test_jarm_and_uri_attributes(self, results):
        doc = to_misp(results)
        vals = {a["value"] for a in doc["Event"]["Attribute"]}
        assert CS in vals
        assert "/submit.php" in vals

    def test_family_tag_and_attack(self, results):
        doc = to_misp(results)
        names = {t["name"] for t in doc["Event"]["Tag"]}
        assert any("cobalt-strike" in n for n in names)
        assert any("T1071.001" in n for n in names)

    def test_dedupe_attributes(self, results):
        doc = to_misp(results)
        pairs = [(a["type"], a["value"]) for a in doc["Event"]["Attribute"]]
        assert len(pairs) == len(set(pairs))

    def test_threat_level_from_worst_severity(self, results):
        # Cobalt Strike is critical → MISP threat_level_id "1".
        assert to_misp(results)["Event"]["threat_level_id"] == "1"

    def test_empty_results(self):
        doc = to_misp([])
        assert doc["Event"]["Attribute"] == []

    def test_deterministic(self, results):
        assert to_misp(results) == to_misp(results)


# --------------------------------------------------------------------------- STIX
class TestSTIX:
    def test_bundle_shape(self, results):
        b = to_stix(results)
        assert b["type"] == "bundle"
        assert b["id"].startswith("bundle--")
        assert b["objects"]

    def test_has_all_sdo_types(self, results):
        b = to_stix(results)
        types = {o["type"] for o in b["objects"]}
        assert {"indicator", "malware", "relationship"} <= types

    def test_indicator_pattern_is_stix(self, results):
        b = to_stix(results)
        inds = [o for o in b["objects"] if o["type"] == "indicator"]
        assert inds
        for i in inds:
            assert i["pattern_type"] == "stix"
            assert i["pattern"].startswith("[") and i["pattern"].endswith("]")
            assert i["kill_chain_phases"][0]["phase_name"] == "command-and-control"

    def test_jarm_in_pattern(self, results):
        b = to_stix(results)
        patterns = " ".join(o["pattern"] for o in b["objects"]
                            if o["type"] == "indicator")
        assert CS in patterns

    def test_relationship_links_indicator_to_malware(self, results):
        b = to_stix(results)
        by_id = {o["id"]: o for o in b["objects"]}
        rels = [o for o in b["objects"] if o["type"] == "relationship"]
        assert rels
        for r in rels:
            assert r["relationship_type"] == "indicates"
            assert by_id[r["source_ref"]]["type"] == "indicator"
            assert by_id[r["target_ref"]]["type"] == "malware"

    def test_malware_is_family(self, results):
        b = to_stix(results)
        mals = [o for o in b["objects"] if o["type"] == "malware"]
        assert mals and all(m["is_family"] for m in mals)

    def test_deterministic_ids(self, results):
        assert to_stix(results) == to_stix(results)

    def test_empty(self):
        b = to_stix([])
        assert b["objects"] == []


class TestSignaturesToSTIX:
    def test_covers_families_with_tls(self):
        b = signatures_to_stix()
        mals = [o for o in b["objects"] if o["type"] == "malware"]
        names = {m["name"] for m in mals}
        assert "Cobalt Strike" in names
        assert "Sliver" in names

    def test_every_indicator_has_relationship(self):
        b = signatures_to_stix()
        inds = [o for o in b["objects"] if o["type"] == "indicator"]
        rels = [o for o in b["objects"] if o["type"] == "relationship"]
        assert len(inds) == len(rels)

    def test_deterministic(self):
        assert signatures_to_stix() == signatures_to_stix()


class TestStixEscaping:
    def test_singlequote_and_backslash_escaped(self):
        from c2detect.core import Signature, scan_observation, Observation
        from c2detect.export import to_stix
        sig = Signature(family="Weird", cert_quirks=("O'Brien\\x",))
        obs = Observation(host="h", cert="subject: O'Brien\\x", port=443)
        res = scan_observation(obs, threshold=1, db=[sig])
        bundle = to_stix([res])
        pat = " ".join(o["pattern"] for o in bundle["objects"]
                       if o["type"] == "indicator")
        # backslash doubled, single-quote escaped — no unescaped breakout
        assert "\\\\" in pat
        assert "\\'" in pat

    def test_nonnumeric_port_dropped(self):
        from c2detect.core import Match, MatchedIndicator, ScanResult, Observation
        from c2detect.export import _stix_pattern
        m = Match(family="F", severity="high", confidence=50, description="",
                  indicators=[MatchedIndicator("port", "https", "https", 6)],
                  references=())
        # a non-numeric port must not emit `dst_port = https`
        pat = _stix_pattern(m, "")
        assert pat is None or "dst_port = https" not in pat


def test_uuid5_shape_and_stable():
    u = _uuid5("seed")
    assert re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-", u)
    assert _uuid5("seed") == u
    assert _uuid5("other") != u


def test_public_api_exports():
    import c2detect
    assert callable(c2detect.to_misp)
    assert callable(c2detect.to_stix)
    assert callable(c2detect.signatures_to_stix)
