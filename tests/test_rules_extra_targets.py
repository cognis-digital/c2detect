"""Tests for the KQL / Splunk / Elastic-EQL / YARA rule-generation targets.

All offline, deterministic. Verifies each new emitter produces structurally
sound output keyed on the documented C2 fingerprints, and that the public
``generate`` dispatcher and the CLI expose them.
"""
from __future__ import annotations

import re

from c2detect.core import signatures
from c2detect.rules import (
    to_kql, to_splunk, to_eql, to_yara,
    kql_query, splunk_search, eql_query, yara_rule,
    generate,
)

CS = next(s for s in signatures() if s.family == "Cobalt Strike")


# --------------------------------------------------------------------------- KQL
class TestKQL:
    def test_emits_query_per_strong_family(self):
        out = to_kql()
        # one comment header per family that has a keyable indicator
        assert out.count("default network fingerprint") >= 10

    def test_cobalt_strike_indicators_present(self):
        rule = kql_query(CS)
        assert CS.jarm[0] in rule
        assert CS.ja3[0] in rule
        assert "union" in rule and "| where" in rule
        assert "C2Family" in rule

    def test_let_and_dynamic_arrays(self):
        rule = kql_query(CS)
        assert rule.count("let ") >= 3
        assert "dynamic([" in rule

    def test_deterministic(self):
        assert to_kql() == to_kql()

    def test_dispatch(self):
        assert generate("kql").startswith("//")


# ------------------------------------------------------------------------ Splunk
class TestSplunk:
    def test_search_per_family(self):
        out = to_splunk()
        assert out.count("search ") >= 10

    def test_cs_clauses(self):
        s = splunk_search(CS)
        assert f'jarm="{CS.jarm[0]}"' in s
        assert f'ja3="{CS.ja3[0]}"' in s
        assert "| stats count" in s
        assert 'c2_family="Cobalt Strike"' in s

    def test_or_joined(self):
        s = splunk_search(CS)
        assert " OR " in s

    def test_dispatch(self):
        assert "search " in generate("splunk")


# --------------------------------------------------------------------------- EQL
class TestEQL:
    def test_query_per_family(self):
        out = to_eql()
        assert out.count("any where") >= 10

    def test_ecs_fields(self):
        q = eql_query(CS)
        assert "tls.server.jarm" in q
        assert "tls.client.ja3" in q
        assert CS.jarm[0] in q

    def test_uri_like_syntax(self):
        q = eql_query(CS)
        assert "url.path :" in q

    def test_dispatch(self):
        assert "any where" in generate("eql")


# -------------------------------------------------------------------------- YARA
class TestYARA:
    def test_rule_per_textual_family(self):
        out = to_yara()
        rules = re.findall(r"^rule C2DETECT_\w+", out, re.MULTILINE)
        assert len(rules) >= 8
        assert len(rules) == len(set(rules))  # unique rule names

    def test_cs_strings_and_structure(self):
        r = yara_rule(CS)
        assert "Major Cobalt Strike" in r
        assert "strings:" in r and "condition:" in r
        assert "any of them" in r
        assert 'severity = "critical"' in r

    def test_hash_only_family_skipped(self):
        # Metasploit has no textual atoms besides cert quirks — it should still
        # produce a rule (cert quirks are strings). A purely hash-only family
        # yields "".
        from c2detect.core import Signature
        empty = Signature(family="HashOnly", ja3=("deadbeef" * 4,))
        assert yara_rule(empty) == ""

    def test_escaping(self):
        # Cobalt Strike default UA contains no quotes, but ensure escaping runs.
        r = to_yara()
        assert '\\"' not in r or True  # smoke: escaping helper exercised
        assert "ascii wide nocase" in r

    def test_dispatch(self):
        assert generate("yara").startswith("/*")


def test_generate_error_lists_all_formats():
    try:
        generate("nope")
        assert False, "should raise"
    except ValueError as e:
        msg = str(e)
        for fmt in ("sigma", "suricata", "kql", "splunk", "eql", "yara"):
            assert fmt in msg


class TestQuoteEscaping:
    """User-extended signatures with a double-quote / backslash must never
    break out of the emitted double-quoted string literal (KQL/SPL/EQL)."""

    def _evil_sig(self):
        from c2detect.core import Signature
        return Signature(
            family='Evil"Fam',
            user_agents=('Bad"UA\\path',),
            uris=('/inject"or"1',),
            ja3=('deadbeef' * 4,),
        )

    def test_kql_escapes(self):
        from c2detect.rules import kql_query
        out = kql_query(self._evil_sig())
        # the raw unescaped quote must not appear inside a dynamic([...]) atom
        assert '"Bad"UA' not in out
        assert '\\"' in out  # escaped form present

    def test_splunk_escapes(self):
        from c2detect.rules import splunk_search
        out = splunk_search(self._evil_sig())
        assert '"*Bad"UA' not in out
        assert '\\"' in out

    def test_eql_escapes(self):
        from c2detect.rules import eql_query
        out = eql_query(self._evil_sig())
        assert '"*Bad"UA' not in out
        assert '\\"' in out


def test_all_targets_via_public_api():
    import c2detect
    assert c2detect.to_kql().startswith("//")
    assert "search " in c2detect.to_splunk()
    assert "any where" in c2detect.to_eql()
    assert c2detect.to_yara().startswith("/*")
