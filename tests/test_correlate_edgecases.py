"""Edge-case coverage for the correlation engine (beyond test_correlate.py).

Focus: degenerate batches (empty / singleton / all-identical), the edge-floor
and campaign-threshold boundaries, cert-serial/CN extraction corner cases,
renderer robustness on empty input, and determinism of campaign IDs. Standard
library only.
"""

from __future__ import annotations

import json

from c2detect.core import Observation, scan_observation, scan_observations
from c2detect.correlate import (
    DEFAULT_EDGE_FLOOR,
    PIVOT_WEIGHTS,
    _cert_cn,
    _cert_serial,
    correlate,
    correlate_observations,
    to_dot,
    to_json,
    to_table,
)

CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"


def _scan(records):
    return scan_observations(records, threshold=35)


# --------------------------------------------------------------------------- #
# Degenerate batches
# --------------------------------------------------------------------------- #
class TestDegenerate:
    def test_empty_batch(self):
        assert correlate([]) == []

    def test_single_host_no_campaign(self):
        assert correlate(_scan([{"jarm": CS_JARM}])) == []

    def test_single_host_with_singletons(self):
        camps = correlate(_scan([{"jarm": CS_JARM}]), include_singletons=True)
        assert len(camps) == 1 and camps[0].size == 1

    def test_two_unrelated_hosts_no_campaign(self):
        recs = [{"host": "a", "jarm": CS_JARM},
                {"host": "b", "port": 9999}]
        assert correlate(_scan(recs)) == []

    def test_two_hosts_shared_jarm_cluster(self):
        recs = [{"host": "a", "jarm": CS_JARM},
                {"host": "b", "jarm": CS_JARM}]
        camps = correlate(_scan(recs))
        assert len(camps) == 1 and camps[0].size == 2

    def test_all_identical_hosts_one_campaign(self):
        recs = [{"host": f"h{i}", "jarm": CS_JARM} for i in range(5)]
        camps = correlate(_scan(recs))
        assert len(camps) == 1 and camps[0].size == 5


# --------------------------------------------------------------------------- #
# Edge-floor / threshold boundaries
# --------------------------------------------------------------------------- #
class TestBoundaries:
    def test_shared_port_alone_below_floor(self):
        recs = [{"host": "a", "port": 443}, {"host": "b", "port": 443}]
        assert correlate(_scan(recs)) == []

    def test_lower_edge_floor_admits_weak_link(self):
        recs = [{"host": "a", "ja3": "a" * 32}, {"host": "b", "ja3": "a" * 32}]
        # shared ja3 weight is 22; with default floor 24 it does not link...
        assert correlate(_scan(recs), edge_floor=DEFAULT_EDGE_FLOOR) == []
        # ...but a floor of 20 admits the edge (also drop the campaign-confidence
        # floor below 22 so the formed campaign is reported, not filtered).
        assert len(correlate(_scan(recs), edge_floor=20,
                             campaign_threshold=10)) == 1

    def test_high_campaign_threshold_filters(self):
        recs = [{"host": "a", "jarm": CS_JARM}, {"host": "b", "jarm": CS_JARM}]
        # JARM edge weight 40 < a threshold of 99 => filtered out.
        assert correlate(_scan(recs), campaign_threshold=99) == []

    def test_campaign_confidence_never_exceeds_100(self):
        recs = [{"host": f"h{i}", "jarm": CS_JARM,
                 "cert": "CN=x serial: abcd1234", "ja4s": "t130200_1301_a56c5b993250"}
                for i in range(8)]
        camps = correlate(_scan(recs))
        assert camps and all(0 <= c.confidence <= 100 for c in camps)


# --------------------------------------------------------------------------- #
# cert serial / CN extraction corners
# --------------------------------------------------------------------------- #
class TestCertExtraction:
    def test_serial_colon_hex(self):
        assert _cert_serial("serial: 0A:1B:2C") == "0a1b2c"

    def test_serial_serialnumber_eq(self):
        assert _cert_serial("serialNumber=DEADBEEF") == "deadbeef"

    def test_serial_absent(self):
        assert _cert_serial("CN=foo only") == ""

    def test_serial_empty(self):
        assert _cert_serial("") == ""

    def test_cn_basic(self):
        assert _cert_cn("CN=example.test, O=Acme") == "example.test"

    def test_cn_with_trailing_serial_not_swallowed(self):
        # CN must stop before a following key:value token.
        assert _cert_cn("CN=foo serial: 1234") == "foo"

    def test_cn_slash_delimited(self):
        assert _cert_cn("/CN=foo/O=bar") == "foo"

    def test_cn_absent(self):
        assert _cert_cn("O=org only") == ""

    def test_reused_serial_is_strongest_pivot(self):
        recs = [{"host": "a", "cert": "CN=x serial: cafebabe"},
                {"host": "b", "cert": "CN=y serial: cafebabe"}]
        camps = correlate(_scan(recs))
        assert len(camps) == 1
        assert "cert_serial" in camps[0].shared


# --------------------------------------------------------------------------- #
# Renderer robustness
# --------------------------------------------------------------------------- #
class TestRenderers:
    def test_to_json_empty(self):
        doc = to_json([])
        assert doc["campaign_count"] == 0 and doc["campaigns"] == []

    def test_to_table_empty_message(self):
        assert "no shared-infrastructure" in to_table([])

    def test_to_dot_empty_is_valid_graph(self):
        dot = to_dot([])
        assert dot.startswith("graph c2campaigns {")
        assert dot.rstrip().endswith("}")

    def test_to_dot_escapes_quotes_in_host(self):
        recs = [{"host": 'weird"name', "jarm": CS_JARM},
                {"host": "b", "jarm": CS_JARM}]
        dot = to_dot(correlate(_scan(recs)))
        assert '\\"' in dot

    def test_as_dict_json_round_trips(self):
        recs = [{"host": "a", "jarm": CS_JARM}, {"host": "b", "jarm": CS_JARM}]
        camps = correlate(_scan(recs))
        doc = to_json(camps)
        assert json.loads(json.dumps(doc))["campaign_count"] == 1

    def test_to_json_document_shape(self):
        recs = [{"host": "a", "jarm": CS_JARM}, {"host": "b", "jarm": CS_JARM}]
        doc = to_json(correlate(_scan(recs)))
        assert doc["tool"] == "c2detect" and doc["mode"] == "correlate"


# --------------------------------------------------------------------------- #
# Determinism + convenience API
# --------------------------------------------------------------------------- #
class TestDeterminismAndConvenience:
    def test_campaign_ids_deterministic(self):
        recs = [{"host": f"h{i}", "jarm": CS_JARM} for i in range(4)]
        a = [c.cid for c in correlate(_scan(recs))]
        b = [c.cid for c in correlate(_scan(recs))]
        assert a == b == list(range(len(a)))

    def test_correlate_observations_convenience(self):
        obs = [Observation(host="a", jarm=CS_JARM),
               Observation(host="b", jarm=CS_JARM)]
        camps = correlate_observations(obs)
        assert len(camps) == 1 and camps[0].size == 2

    def test_pivot_weights_strictly_ordered_strong_over_weak(self):
        assert PIVOT_WEIGHTS["cert_serial"] > PIVOT_WEIGHTS["jarm"]
        assert PIVOT_WEIGHTS["jarm"] > PIVOT_WEIGHTS["port"]

    def test_campaigns_sorted_largest_first(self):
        recs = ([{"host": f"big{i}", "jarm": CS_JARM} for i in range(4)]
                + [{"host": "s1", "cert": "serial: aaaa1111"},
                   {"host": "s2", "cert": "serial: aaaa1111"}])
        camps = correlate(_scan(recs))
        assert len(camps) == 2
        assert camps[0].size >= camps[1].size
