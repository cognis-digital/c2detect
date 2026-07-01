"""Edge-case and determinism coverage for the Sigma / Suricata rule generator.

Focus: rule-gen determinism (stable UUIDs/SIDs across runs), families with no
strong indicator (graceful empty rule), custom signature DBs, SID range/uniqueness
invariants, and the dispatch error path. Standard library only.
"""

from __future__ import annotations

import re

import pytest

from c2detect.core import Signature, signatures
from c2detect.rules import (
    generate,
    sigma_rule,
    suricata_rules,
    to_sigma,
    to_suricata,
)

CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"


# --------------------------------------------------------------------------- #
# Determinism — the headline guarantee for committed rule packs.
# --------------------------------------------------------------------------- #
class TestDeterminism:
    def test_sigma_byte_identical_across_runs(self):
        assert to_sigma() == to_sigma()

    def test_suricata_byte_identical_across_runs(self):
        assert to_suricata() == to_suricata()

    def test_sigma_uuid_stable_per_family(self):
        cs = next(s for s in signatures() if s.family == "Cobalt Strike")
        a = re.search(r"^id: ([0-9a-f-]{36})$", sigma_rule(cs), re.MULTILINE)
        b = re.search(r"^id: ([0-9a-f-]{36})$", sigma_rule(cs), re.MULTILINE)
        assert a and b and a.group(1) == b.group(1)

    def test_sigma_uuids_unique_across_db(self):
        ids = re.findall(r"^id: ([0-9a-f-]{36})$", to_sigma(), re.MULTILINE)
        assert len(ids) == len(set(ids))

    def test_suricata_sid_assignment_stable(self):
        sids_a = re.findall(r"sid:(\d+);", to_suricata())
        sids_b = re.findall(r"sid:(\d+);", to_suricata())
        assert sids_a == sids_b


# --------------------------------------------------------------------------- #
# Families with weak / no indicators
# --------------------------------------------------------------------------- #
class TestWeakFamilies:
    def test_no_strong_indicator_yields_empty_rule(self):
        # Only a port — nothing strong enough to key a Sigma rule on.
        sig = Signature(family="PortOnly", ports=(4444,))
        assert sigma_rule(sig) == ""

    def test_short_uri_only_yields_empty_sigma(self):
        # URIs under 5 chars are filtered (too generic for content match).
        sig = Signature(family="ShortUri", uris=("/a", "/b"))
        assert sigma_rule(sig) == ""

    def test_distinctive_uri_falls_back_to_uri_selection(self):
        sig = Signature(family="UriFam", uris=("/agent_message",))
        rule = sigma_rule(sig)
        assert "cs-uri-stem|contains" in rule
        assert "/agent_message" in rule

    def test_user_agent_fallback(self):
        sig = Signature(family="UaFam", user_agents=("NimPlantUA",))
        rule = sigma_rule(sig)
        assert "c-useragent|contains" in rule

    def test_suricata_empty_for_portonly(self):
        sig = Signature(family="PortOnly", ports=(4444,))
        rules, sid = suricata_rules(sig, 9_200_000)
        assert rules == [] and sid == 9_200_000


# --------------------------------------------------------------------------- #
# Custom signature DBs
# --------------------------------------------------------------------------- #
class TestCustomDB:
    def test_to_sigma_empty_db(self):
        assert to_sigma(()) == ""

    def test_to_suricata_empty_db_has_header_only(self):
        out = to_suricata(())
        assert "generated Suricata rules" in out
        assert not [l for l in out.splitlines() if l.startswith("alert ")]

    def test_to_sigma_single_family(self):
        sig = Signature(family="Solo", ja3=("a" * 32,))
        out = to_sigma((sig,))
        assert "title: C2DETECT — Solo" in out
        assert ("a" * 32) in out

    def test_to_suricata_single_family_sid_base(self):
        sig = Signature(family="Solo", ja3=("a" * 32,))
        out = to_suricata((sig,))
        sids = [int(s) for s in re.findall(r"sid:(\d+);", out)]
        assert sids and sids[0] == 9_200_000


# --------------------------------------------------------------------------- #
# Suricata invariants
# --------------------------------------------------------------------------- #
class TestSuricataInvariants:
    def test_all_sids_in_private_band(self):
        sids = [int(s) for s in re.findall(r"sid:(\d+);", to_suricata())]
        assert all(9_200_000 <= s < 9_300_000 for s in sids)

    def test_all_sids_unique(self):
        sids = [int(s) for s in re.findall(r"sid:(\d+);", to_suricata())]
        assert len(sids) == len(set(sids))

    def test_every_alert_well_formed(self):
        for line in (l for l in to_suricata().splitlines() if l.startswith("alert ")):
            assert line.endswith(")")
            assert "msg:" in line and "sid:" in line and "rev:1;" in line

    def test_user_agent_quotes_escaped(self):
        sig = Signature(family="QuoteFam", user_agents=('Mozilla "5.0"',))
        rules, _ = suricata_rules(sig, 9_200_000)
        assert any('\\"5.0\\"' in r for r in rules)

    def test_sid_monotonic_within_family(self):
        sig = Signature(family="Multi", ja3=("a" * 32, "b" * 32))
        rules, nxt = suricata_rules(sig, 9_200_000)
        sids = [int(re.search(r"sid:(\d+);", r).group(1)) for r in rules]
        assert sids == [9_200_000, 9_200_001]
        assert nxt == 9_200_002


# --------------------------------------------------------------------------- #
# Dispatch + errors
# --------------------------------------------------------------------------- #
class TestDispatch:
    def test_generate_sigma(self):
        assert generate("sigma").startswith("title:")

    def test_generate_suricata(self):
        assert "alert " in generate("suricata")

    def test_generate_case_insensitive(self):
        assert generate("SIGMA").startswith("title:")

    def test_generate_unknown_raises(self):
        with pytest.raises(ValueError):
            generate("yaml")

    def test_generate_unknown_message_mentions_options(self):
        with pytest.raises(ValueError, match="sigma.*suricata|suricata.*sigma"):
            generate("xml")
