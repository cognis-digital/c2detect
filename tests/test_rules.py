"""Tests for the Sigma / Suricata detection-rule generator."""

import re

from c2detect.core import signatures
from c2detect.rules import to_sigma, to_suricata, sigma_rule, generate


def test_signatures_accessor_nonempty():
    sigs = signatures()
    assert len(sigs) >= 10
    assert any(s.family == "Cobalt Strike" for s in sigs)


def test_sigma_has_rule_per_strong_family():
    out = to_sigma()
    # one document per family separated by '---'
    docs = [d for d in out.split("\n---\n") if d.strip()]
    assert len(docs) >= 10
    assert "title: C2DETECT — Cobalt Strike" in out
    assert "attack.command_and_control" in out


def test_sigma_includes_tls_fingerprints():
    cs = next(s for s in signatures() if s.family == "Cobalt Strike")
    rule = sigma_rule(cs)
    # the documented CS JA3 must appear in its rule
    assert cs.ja3[0] in rule
    assert "logsource:" in rule
    assert "condition:" in rule


def test_sigma_ids_are_stable_and_unique():
    out = to_sigma()
    ids = re.findall(r"^id: ([0-9a-f-]{36})$", out, re.MULTILINE)
    assert len(ids) == len(set(ids))           # unique
    assert to_sigma() == out                   # deterministic across runs


def test_suricata_valid_structure():
    out = to_suricata()
    lines = [l for l in out.splitlines() if l.startswith("alert ")]
    assert len(lines) >= 10
    for l in lines:
        assert l.endswith(")")
        assert "sid:" in l and "rev:1;" in l
        assert "msg:" in l


def test_suricata_sids_unique_and_in_range():
    out = to_suricata()
    sids = [int(m) for m in re.findall(r"sid:(\d+);", out)]
    assert len(sids) == len(set(sids))
    assert all(9_200_000 <= s < 9_300_000 for s in sids)


def test_suricata_has_ja3_and_uri_rules():
    out = to_suricata()
    assert "ja3.hash; content:" in out
    assert "http.uri; content:" in out


def test_generate_dispatch_and_error():
    assert generate("sigma").startswith("title:")
    assert "alert " in generate("suricata")
    try:
        generate("yaml")
        assert False, "should have raised"
    except ValueError:
        pass
