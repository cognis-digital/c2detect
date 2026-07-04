"""Tests for the feed-aggregation detector pack (parsers on fixtures; no network)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from c2detect import detectorpack as dp  # noqa: E402

THREATFOX = ('"first_seen","ioc_id","ioc_value","ioc_type","threat_type","malware",'
             '"conf","ref"\n'
             '"2026-07-01","1","1.2.3.4:443","ip:port","botnet_cc","CobaltStrike","100","x"\n'
             '"2026-07-01","2","bad.example.com","domain","botnet_cc","QakBot","90","y"\n'
             '"2026-07-01","3","http://evil.example/p","url","payload_delivery","IcedID","75","z"\n')
FEODO = '# feodo\n"first_seen","dst_ip","dst_port","malware"\n"2026-07-01","203.0.113.9","443","Emotet"\n'
SSLBL = '# ja3\n"ts","ja3","reason"\n"2026-07-01","e7d705a3286e19ea42f587b344ee6865","CobaltStrike C2"\n'
URLHAUS = '# urlhaus\n"id","dateadded","url","status"\n"1","2026-07-01","http://mal.example/a.exe","online"\n'


def test_parse_threatfox():
    d = dp.parse_threatfox(THREATFOX)
    kinds = {x["kind"] for x in d}
    assert {"ipv4", "domain", "url"} <= kinds
    ip = next(x for x in d if x["kind"] == "ipv4")
    assert ip["value"] == "1.2.3.4" and ip["family"] == "CobaltStrike"


def test_parse_feodo_sslbl_urlhaus():
    assert dp.parse_feodo(FEODO)[0]["value"] == "203.0.113.9"
    j = dp.parse_sslbl_ja3(SSLBL)[0]
    assert j["kind"] == "ja3" and len(j["value"]) == 32
    assert dp.parse_urlhaus(URLHAUS)[0]["kind"] == "url"


def test_stats_shape():
    dets = dp.parse_threatfox(THREATFOX) + dp.parse_feodo(FEODO)
    s = dp.stats(dets)
    assert s["total"] == len(dets)
    assert "ipv4" in s["by_kind"] and s["families"] >= 1


def test_offline_snapshot_bundled():
    """The bundled snapshot exists and carries thousands of C2-relevant detectors."""
    dets = dp.build(offline=True)
    assert len(dets) >= 3000
    kinds = {d["kind"] for d in dets}
    assert "ipv4" in kinds and "ja3" in kinds
