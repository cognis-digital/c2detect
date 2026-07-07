"""Edge-case and error-path coverage for c2detect.core.

These exercise the inputs real telemetry throws at the engine: malformed
records, unknown / absent C2 families, empty feeds, weird field types, regex
edge cases, and the determinism guarantees the rest of the suite leans on.
Standard library only; no network.
"""

from __future__ import annotations

import json

import pytest

from c2detect.core import (
    DEFAULT_THRESHOLD,
    Observation,
    Signature,
    fails_gate,
    list_signatures,
    load_records,
    observation_from_record,
    observation_from_text,
    scan_observation,
    scan_observations,
    scan_text,
    signatures,
    to_badge,
    to_html,
    to_sarif,
    worst_severity,
)

CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"


# --------------------------------------------------------------------------- #
# observation_from_record — malformed / hostile records
# --------------------------------------------------------------------------- #
class TestMalformedRecords:
    def test_empty_dict(self):
        obs = observation_from_record({})
        assert obs.host == "" and obs.port is None and obs.uris == []

    def test_none_values_ignored(self):
        obs = observation_from_record(
            {"host": None, "ja3": None, "port": None, "uris": None})
        assert obs.host == "" and obs.ja3 == "" and obs.port is None

    def test_empty_string_values_ignored(self):
        obs = observation_from_record({"host": "", "ja3": "", "jarm": ""})
        assert obs.host == "" and obs.jarm == ""

    def test_port_garbage_string(self):
        obs = observation_from_record({"port": "not-a-port"})
        assert obs.port is None

    def test_port_embedded_number(self):
        obs = observation_from_record({"port": "tcp/8443"})
        assert obs.port == 8443

    def test_port_float_like(self):
        obs = observation_from_record({"port": 443.0})
        assert obs.port == 443

    def test_numeric_ja3_coerced_to_str(self):
        obs = observation_from_record({"ja3": 12345})
        assert obs.ja3 == "12345"

    def test_uri_single_string(self):
        obs = observation_from_record({"uri": "/submit.php"})
        assert obs.uris == ["/submit.php"]

    def test_uri_list_mixed_with_none(self):
        obs = observation_from_record({"uris": ["/a", None, "", "/b"]})
        assert obs.uris == ["/a", "/b"]

    def test_unknown_keys_ignored(self):
        obs = observation_from_record({"totally_unknown_field": "x", "ja3": "abc"})
        assert obs.ja3 == "abc"

    def test_jitter_percent_normalized(self):
        assert observation_from_record({"jitter": 15}).jitter == pytest.approx(0.15)

    def test_jitter_fraction_kept(self):
        assert observation_from_record({"jitter": 0.15}).jitter == pytest.approx(0.15)

    def test_jitter_percent_string(self):
        assert observation_from_record({"jitter": "30%"}).jitter == pytest.approx(0.30)

    def test_beacon_interval_garbage(self):
        # No digits at all -> stays None rather than raising.
        assert observation_from_record({"beacon_interval": "soon"}).beacon_interval is None

    def test_beacon_interval_embedded(self):
        assert observation_from_record({"sleep": "60s"}).beacon_interval == 60.0

    def test_field_aliases_dest_ip(self):
        assert observation_from_record({"dest_ip": "1.2.3.4"}).host == "1.2.3.4"

    def test_field_aliases_server_port(self):
        assert observation_from_record({"server_port": 8888}).port == 8888

    def test_cert_blob_merges_multiple_aliases(self):
        obs = observation_from_record({"subject": "CN=foo", "issuer": "CN=bar"})
        assert "CN=foo" in obs.cert and "CN=bar" in obs.cert

    def test_as_dict_round_trips(self):
        obs = observation_from_record({"host": "h", "ja3": CS_JARM[:32], "port": 443})
        d = obs.as_dict()
        assert d["host"] == "h" and d["port"] == 443
        assert json.loads(json.dumps(d))["host"] == "h"


# --------------------------------------------------------------------------- #
# Unknown / absent families
# --------------------------------------------------------------------------- #
class TestUnknownFamilies:
    def test_unknown_jarm_no_match(self):
        res = scan_observation(Observation(jarm="deadbeef" * 7 + "aa"))
        assert res.count == 0 and res.top is None

    def test_random_uri_no_match(self):
        res = scan_observation(Observation(uris=["/totally/benign/path"]))
        assert res.count == 0

    def test_benign_banner_no_match(self):
        res = scan_observation(Observation(http_banner="nginx/1.24.0"))
        assert res.count == 0

    def test_empty_observation_no_match(self):
        assert scan_observation(Observation()).count == 0

    def test_custom_db_with_no_families(self):
        res = scan_observation(Observation(jarm=CS_JARM), db=())
        assert res.count == 0

    def test_custom_db_single_family(self):
        sig = Signature(family="OnlyOne", jarm=(CS_JARM,))
        res = scan_observation(Observation(jarm=CS_JARM), db=(sig,))
        assert res.count == 1 and res.top.family == "OnlyOne"


# --------------------------------------------------------------------------- #
# Empty / degenerate batch inputs
# --------------------------------------------------------------------------- #
class TestEmptyInputs:
    def test_scan_observations_empty_list(self):
        assert scan_observations([]) == []

    def test_to_sarif_empty(self):
        s = to_sarif([])
        assert s["version"] == "2.1.0"
        assert s["runs"][0]["results"] == []
        assert s["runs"][0]["tool"]["driver"]["rules"] == []

    def test_to_badge_empty_is_clean(self):
        b = to_badge([])
        assert b["message"] == "clean" and b["color"] == "brightgreen"

    def test_to_html_empty_is_clean(self):
        html = to_html([])
        assert "<!doctype html>" in html.lower()
        assert "No C2 indicators found" in html

    def test_worst_severity_empty_is_none(self):
        assert worst_severity([]) is None

    def test_fails_gate_empty_never_fails(self):
        assert fails_gate([], "critical") is False

    def test_fails_gate_none_fail_on(self):
        res = scan_observations([{"jarm": CS_JARM}])
        assert fails_gate(res, None) is False


# --------------------------------------------------------------------------- #
# load_records — parser robustness (the JSON vs JSONL vs text fork)
# --------------------------------------------------------------------------- #
class TestLoadRecords:
    def test_plain_text_returns_none(self):
        assert load_records("this is not json at all") is None

    def test_empty_string_returns_none(self):
        assert load_records("") is None

    def test_whitespace_only_returns_none(self):
        assert load_records("   \n\t  ") is None

    def test_bare_list(self):
        recs = load_records('[{"host": "a"}, {"host": "b"}]')
        assert recs is not None and len(recs) == 2

    def test_single_object(self):
        recs = load_records('{"host": "a"}')
        assert recs == [{"host": "a"}]

    def test_observations_wrapper(self):
        recs = load_records('{"observations": [{"host": "a"}]}')
        assert recs == [{"host": "a"}]

    def test_records_wrapper(self):
        recs = load_records('{"records": [{"host": "a"}, {"host": "b"}]}')
        assert len(recs) == 2

    def test_hosts_wrapper(self):
        recs = load_records('{"hosts": [{"host": "a"}]}')
        assert recs == [{"host": "a"}]

    def test_jsonl_stream(self):
        text = '{"host": "a"}\n{"host": "b"}\n{"host": "c"}'
        recs = load_records(text)
        assert recs is not None and len(recs) == 3

    def test_jsonl_with_blank_lines(self):
        text = '{"host": "a"}\n\n{"host": "b"}\n'
        recs = load_records(text)
        assert recs is not None and len(recs) == 2

    def test_jsonl_majority_garbage_returns_none(self):
        # More garbage lines than parseable objects => not a JSONL stream.
        text = "garbage1\ngarbage2\ngarbage3\n{\"host\": \"a\"}"
        assert load_records(text) is None

    def test_list_filters_non_dicts(self):
        recs = load_records('[{"host": "a"}, 42, "str", null]')
        assert recs == [{"host": "a"}]

    def test_malformed_json_not_jsonl_returns_none(self):
        assert load_records('{"host": "a"') is None


# --------------------------------------------------------------------------- #
# observation_from_text — harvester edge cases
# --------------------------------------------------------------------------- #
class TestTextHarvester:
    def test_empty_text(self):
        obs = observation_from_text("")
        assert obs.host == "" and obs.jarm == ""

    def test_free_floating_jarm(self):
        obs = observation_from_text(f"some log {CS_JARM} more")
        assert obs.jarm == CS_JARM

    def test_keyvalue_port(self):
        assert observation_from_text("port: 50050").port == 50050

    def test_keyvalue_host(self):
        assert observation_from_text("host: 1.2.3.4").host == "1.2.3.4"

    def test_uri_paths_harvested(self):
        obs = observation_from_text("GET /submit.php and /__utm.gif")
        assert "/submit.php" in obs.uris

    def test_scan_text_detects_cs(self):
        res = scan_text(f"jarm: {CS_JARM}", threshold=35)
        assert res.top is not None and res.top.family == "Cobalt Strike"

    def test_scan_text_benign(self):
        assert scan_text("nothing to see here", threshold=35).count == 0


# --------------------------------------------------------------------------- #
# Threshold behaviour
# --------------------------------------------------------------------------- #
class TestThreshold:
    def test_high_threshold_suppresses_weak(self):
        # A lone port hit (weight 6) is far below 90.
        res = scan_observation(Observation(port=443), threshold=90)
        assert res.count == 0

    def test_zero_threshold_admits_weak(self):
        res = scan_observation(Observation(port=50050), threshold=0)
        assert res.count >= 1

    def test_negative_threshold_admits_all_hits(self):
        res = scan_observation(Observation(jarm=CS_JARM), threshold=-5)
        assert res.count >= 1

    def test_matches_sorted_by_confidence_desc(self):
        # CS host with strong jarm + cert quirk should outrank weak heuristics.
        res = scan_observation(
            Observation(jarm=CS_JARM, cert="CN=Major Cobalt Strike",
                        port=50050, beacon_interval=60, jitter=0.05),
            threshold=0)
        confs = [m.confidence for m in res.matches]
        assert confs == sorted(confs, reverse=True)
        assert res.top.family == "Cobalt Strike"


# --------------------------------------------------------------------------- #
# Determinism guarantees
# --------------------------------------------------------------------------- #
class TestDeterminism:
    def test_scan_is_deterministic(self):
        obs = {"jarm": CS_JARM, "cert": "CN=Major Cobalt Strike"}
        a = scan_observations([obs])[0].as_dict()
        b = scan_observations([obs])[0].as_dict()
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)

    def test_sarif_is_deterministic(self):
        res = scan_observations([{"jarm": CS_JARM}])
        assert json.dumps(to_sarif(res)) == json.dumps(to_sarif(res))

    def test_list_signatures_stable(self):
        assert list_signatures() == list_signatures()

    def test_signatures_db_nonempty(self):
        assert len(signatures()) >= 12

    def test_confidence_capped_at_100(self):
        # Pile on every strong indicator; confidence must never exceed 100.
        res = scan_observation(
            Observation(jarm=CS_JARM, ja3="a0e9f5d64349fb13191bc781f81f42e1",
                        ja4s="t130200_1301_a56c5b993250",
                        ja3s="e35df3e00ca4ef31d42b34bebaa2f86e",
                        cert="CN=Major Cobalt Strike serial: 146473198",
                        port=50050, uris=["/submit.php"]),
            threshold=0)
        assert all(0 <= m.confidence <= 100 for m in res.matches)
        assert res.top.confidence == 100
