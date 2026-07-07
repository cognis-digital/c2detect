"""Deep coverage of the matching engine: field aliases, scoring corroboration,
severity gating, and the free-text harvester — the behaviours the detection
contract rests on. Standard library only.
"""

from __future__ import annotations

import pytest

from c2detect.core import (
    Observation,
    Signature,
    WEIGHTS,
    fails_gate,
    observation_from_record,
    observation_from_text,
    scan_observation,
    worst_severity,
    scan_observations,
)

CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"
CS_JA3 = "a0e9f5d64349fb13191bc781f81f42e1"


# --------------------------------------------------------------------------- #
# Field aliases — every documented alias maps to its canonical field.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("alias", ["host", "ip", "ip_addr", "dest_ip",
                                   "address", "addr"])
def test_host_aliases(alias):
    assert observation_from_record({alias: "1.2.3.4"}).host == "1.2.3.4"


@pytest.mark.parametrize("alias", ["port", "dest_port", "dst_port", "server_port"])
def test_port_aliases(alias):
    assert observation_from_record({alias: 8443}).port == 8443


@pytest.mark.parametrize("alias", ["user_agent", "useragent", "ua",
                                   "http_user_agent"])
def test_user_agent_aliases(alias):
    assert observation_from_record({alias: "Mozilla/5.0"}).user_agent == "Mozilla/5.0"


@pytest.mark.parametrize("alias", ["uris", "uri", "http_paths", "paths",
                                   "url", "urls"])
def test_uri_aliases_single(alias):
    obs = observation_from_record({alias: "/submit.php"})
    assert "/submit.php" in obs.uris


@pytest.mark.parametrize("alias", ["beacon_interval", "interval", "sleep",
                                   "period", "cadence", "mean_interval",
                                   "beacon_sec"])
def test_beacon_aliases(alias):
    assert observation_from_record({alias: 60}).beacon_interval == 60.0


@pytest.mark.parametrize("alias", ["jitter", "jitter_frac", "jitter_pct",
                                   "variance"])
def test_jitter_aliases(alias):
    assert observation_from_record({alias: 0.1}).jitter == pytest.approx(0.1)


@pytest.mark.parametrize("alias", ["http_banner", "banner", "server_header"])
def test_banner_aliases(alias):
    assert "nginx" in observation_from_record({alias: "nginx"}).http_banner


# --------------------------------------------------------------------------- #
# Scoring: corroboration bonus + per-class dedup.
# --------------------------------------------------------------------------- #
class TestScoring:
    def test_single_strong_indicator_scores(self):
        res = scan_observation(Observation(jarm=CS_JARM), threshold=0)
        cs = next(m for m in res.matches if m.family == "Cobalt Strike")
        assert cs.confidence == WEIGHTS["jarm"]

    def test_two_strong_indicators_get_corroboration_bonus(self):
        res = scan_observation(
            Observation(jarm=CS_JARM, cert="CN=Major Cobalt Strike"), threshold=0)
        cs = next(m for m in res.matches if m.family == "Cobalt Strike")
        # jarm(42) + cert_quirk(28) + 18 corroboration = 88.
        assert cs.confidence == 42 + 28 + 18

    def test_duplicate_uri_class_counts_once(self):
        sig = Signature(family="UriX", uris=("/aaaa", "/bbbb"))
        obs = Observation(uris=["/aaaa", "/bbbb"])
        res = scan_observation(obs, db=(sig,), threshold=0)
        # Two URI hits, but the uri class weight is counted once.
        assert res.top.confidence == WEIGHTS["uri"]

    def test_port_alone_is_weak(self):
        res = scan_observation(Observation(port=50050), threshold=0)
        assert all(m.confidence <= WEIGHTS["port"] + 1 for m in res.matches
                   if all(i.klass == "port" for i in m.indicators))

    def test_matches_sorted_desc(self):
        res = scan_observation(
            Observation(jarm=CS_JARM, port=443, uris=["/submit.php"]),
            threshold=0)
        confs = [m.confidence for m in res.matches]
        assert confs == sorted(confs, reverse=True)


# --------------------------------------------------------------------------- #
# Severity gating
# --------------------------------------------------------------------------- #
class TestSeverityGate:
    def test_worst_severity_picks_most_severe(self):
        res = scan_observations([{"jarm": CS_JARM},          # critical (CS)
                                 {"port": 7443}])             # lower heuristics
        assert worst_severity(res) == "critical"

    def test_fails_gate_critical_on_cs(self):
        res = scan_observations([{"jarm": CS_JARM}])
        assert fails_gate(res, "critical") is True

    def test_fails_gate_high_floor_admits_critical(self):
        res = scan_observations([{"jarm": CS_JARM}])
        assert fails_gate(res, "high") is True

    def test_fails_gate_no_match(self):
        res = scan_observations([{"host": "x", "port": 12345}])
        assert fails_gate(res, "info") is False

    def test_fails_gate_unknown_floor_is_most_permissive(self):
        res = scan_observations([{"jarm": CS_JARM}])
        # An unrecognized floor maps to rank 99 (the lowest priority), so every
        # match clears it. The CLI never reaches this (argparse 'choices' guards
        # --fail-on); this pins the library-level contract.
        assert fails_gate(res, "nonsense") is True

    def test_fails_gate_falsy_floor_never_fails(self):
        res = scan_observations([{"jarm": CS_JARM}])
        assert fails_gate(res, "") is False
        assert fails_gate(res, None) is False


# --------------------------------------------------------------------------- #
# Free-text harvester matrix
# --------------------------------------------------------------------------- #
class TestHarvester:
    def test_keyvalue_jarm(self):
        assert observation_from_text(f"jarm: {CS_JARM}").jarm == CS_JARM

    def test_keyvalue_ja3(self):
        assert observation_from_text(f"ja3: {CS_JA3}").ja3 == CS_JA3

    def test_keyvalue_multiple_pairs(self):
        obs = observation_from_text(f"host: 1.2.3.4  port: 443  jarm: {CS_JARM}")
        assert obs.host == "1.2.3.4" and obs.port == 443 and obs.jarm == CS_JARM

    def test_banner_keyvalue(self):
        assert "beacondata" in observation_from_text("banner: BeaconData").http_banner.lower()

    def test_ua_keyvalue(self):
        assert "nimplant" in observation_from_text("ua: NimPlant").user_agent.lower()

    def test_beacon_interval_keyvalue(self):
        assert observation_from_text("interval: 60s").beacon_interval == 60.0

    def test_jitter_percent_keyvalue(self):
        assert observation_from_text("jitter: 10%").jitter == pytest.approx(0.10)

    def test_free_floating_uris(self):
        obs = observation_from_text("GET /submit.php then /__utm.gif")
        assert "/submit.php" in obs.uris and "/__utm.gif" in obs.uris

    def test_text_scan_detects_cs_jarm(self):
        res = scan_observation(observation_from_text(f"weird tls {CS_JARM}"),
                               threshold=35)
        assert res.top and res.top.family == "Cobalt Strike"

    def test_empty_text_no_match(self):
        assert scan_observation(observation_from_text(""), threshold=35).count == 0
