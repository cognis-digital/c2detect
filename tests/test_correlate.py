"""Tests for the C2DETECT correlation engine (cross-host campaign clustering).

Standard library only. NO network: all inputs are synthetic-for-tests
fingerprints / committed fixtures. The Cobalt Strike / Metasploit JARM
constants are publicly documented defaults reused across the existing suite.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from c2detect import (  # noqa: E402
    Observation,
    correlate,
    correlate_observations,
    scan_observation,
    Campaign,
    PIVOT_WEIGHTS,
)
from c2detect import correlate as corr_mod  # noqa: E402
from c2detect.correlate import (  # noqa: E402
    _features,
    _shared_pivots,
    _edge_weight,
    _cert_serial,
    _cert_cn,
    _DSU,
    to_table,
    to_json,
    to_dot,
    DEFAULT_EDGE_FLOOR,
    DEFAULT_CAMPAIGN_THRESHOLD,
)
from c2detect.cli import main  # noqa: E402
from c2detect import mcp_server  # noqa: E402

CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"
MSF_JARM = "07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d"
FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "campaign_obs.json")


def _scan(obs_list, threshold=1):
    return [scan_observation(o, threshold=threshold) for o in obs_list]


# --------------------------------------------------------------------------- #
# Cert helpers
# --------------------------------------------------------------------------- #
class TestCertHelpers(unittest.TestCase):
    def test_cert_serial_colon_hex(self):
        self.assertEqual(_cert_serial("serial: 0A:1B:2C"), "0a1b2c")

    def test_cert_serial_serialnumber_eq(self):
        self.assertEqual(_cert_serial("serialNumber=DEADBEEF"), "deadbeef")

    def test_cert_serial_none(self):
        self.assertEqual(_cert_serial("CN=foo no serial here"), "")

    def test_cert_serial_empty(self):
        self.assertEqual(_cert_serial(""), "")

    def test_cert_cn_basic(self):
        self.assertEqual(_cert_cn("CN=Update.Example.Test, O=x"), "update.example.test")

    def test_cert_cn_slash_delim(self):
        self.assertEqual(_cert_cn("/CN=foo.bar/O=baz"), "foo.bar")

    def test_cert_cn_none(self):
        self.assertEqual(_cert_cn("issuer=somebody"), "")


# --------------------------------------------------------------------------- #
# Feature extraction
# --------------------------------------------------------------------------- #
class TestFeatures(unittest.TestCase):
    def test_jarm_pivot_extracted(self):
        r = scan_observation(Observation(host="h1", jarm=CS_JARM), threshold=1)
        node = _features(r, 0)
        self.assertIn(CS_JARM.lower(), node.pivot_values("jarm"))

    def test_family_pivot_from_detection(self):
        r = scan_observation(Observation(host="h1", jarm=CS_JARM), threshold=1)
        node = _features(r, 0)
        self.assertTrue(node.family)
        self.assertIn(node.family.lower(), node.pivot_values("family"))

    def test_host_fallback_label(self):
        r = scan_observation(Observation(jarm=CS_JARM), threshold=1)
        node = _features(r, 3)
        self.assertEqual(node.host, "obs[3]")

    def test_cert_serial_and_cn_pivots(self):
        r = scan_observation(
            Observation(host="h", cert="CN=evil.test serial: ABCD"), threshold=1)
        node = _features(r, 0)
        self.assertIn("abcd", node.pivot_values("cert_serial"))
        self.assertIn("evil.test", node.pivot_values("cert_cn"))

    def test_beacon_bucketed(self):
        r = scan_observation(Observation(host="h", beacon_interval=62), threshold=1)
        node = _features(r, 0)
        # 62 rounds to nearest 5 -> 60
        self.assertIn("60", node.pivot_values("beacon"))

    def test_port_pivot(self):
        r = scan_observation(Observation(host="h", port=8443), threshold=1)
        node = _features(r, 0)
        self.assertIn("8443", node.pivot_values("port"))

    def test_uri_pivot(self):
        r = scan_observation(Observation(host="h", uris=["/submit.php"]), threshold=1)
        node = _features(r, 0)
        self.assertIn("/submit.php", node.pivot_values("uri"))

    def test_empty_obs_no_pivots(self):
        r = scan_observation(Observation(host="h"), threshold=1)
        node = _features(r, 0)
        self.assertEqual(node.pivots, {})


# --------------------------------------------------------------------------- #
# Shared-pivot computation + edge weighting
# --------------------------------------------------------------------------- #
class TestSharedPivots(unittest.TestCase):
    def test_shared_jarm(self):
        a = _features(scan_observation(Observation(host="a", jarm=CS_JARM), 1), 0)
        b = _features(scan_observation(Observation(host="b", jarm=CS_JARM), 1), 1)
        piv = _shared_pivots(a, b)
        klasses = {p.klass for p in piv}
        self.assertIn("jarm", klasses)

    def test_different_jarm_no_share(self):
        a = _features(scan_observation(Observation(host="a", jarm=CS_JARM), 1), 0)
        b = _features(scan_observation(Observation(host="b", jarm=MSF_JARM), 1), 1)
        piv = _shared_pivots(a, b)
        self.assertNotIn("jarm", {p.klass for p in piv})

    def test_edge_weight_dedups_class(self):
        # Two pivots same class -> max weight once, not summed.
        from c2detect.correlate import SharedPivot
        ps = [SharedPivot("jarm", "x", 40), SharedPivot("jarm", "y", 40)]
        self.assertEqual(_edge_weight(ps), 40)

    def test_edge_weight_sums_distinct_classes(self):
        from c2detect.correlate import SharedPivot
        ps = [SharedPivot("jarm", "x", 40), SharedPivot("port", "443", 4)]
        self.assertEqual(_edge_weight(ps), 44)

    def test_shared_port_only_below_floor(self):
        a = _features(scan_observation(Observation(host="a", port=443), 1), 0)
        b = _features(scan_observation(Observation(host="b", port=443), 1), 1)
        piv = _shared_pivots(a, b)
        self.assertLess(_edge_weight(piv), DEFAULT_EDGE_FLOOR)

    def test_pivot_weights_ordered(self):
        # Cert serial is the strongest pivot; port is the weakest.
        self.assertGreater(PIVOT_WEIGHTS["cert_serial"], PIVOT_WEIGHTS["jarm"])
        self.assertGreater(PIVOT_WEIGHTS["jarm"], PIVOT_WEIGHTS["port"])


# --------------------------------------------------------------------------- #
# Union-Find
# --------------------------------------------------------------------------- #
class TestDSU(unittest.TestCase):
    def test_union_find_basic(self):
        d = _DSU(4)
        d.union(0, 1)
        d.union(2, 3)
        self.assertEqual(d.find(0), d.find(1))
        self.assertEqual(d.find(2), d.find(3))
        self.assertNotEqual(d.find(0), d.find(2))

    def test_transitive_union(self):
        d = _DSU(3)
        d.union(0, 1)
        d.union(1, 2)
        self.assertEqual(d.find(0), d.find(2))

    def test_singleton(self):
        d = _DSU(2)
        self.assertNotEqual(d.find(0), d.find(1))


# --------------------------------------------------------------------------- #
# correlate() core behavior
# --------------------------------------------------------------------------- #
class TestCorrelate(unittest.TestCase):
    def test_shared_jarm_clusters_two_hosts(self):
        results = _scan([
            Observation(host="a", jarm=CS_JARM),
            Observation(host="b", jarm=CS_JARM),
        ])
        camps = correlate(results)
        self.assertEqual(len(camps), 1)
        self.assertEqual(camps[0].size, 2)
        self.assertIn("a", camps[0].hosts)
        self.assertIn("b", camps[0].hosts)

    def test_unrelated_hosts_no_campaign(self):
        results = _scan([
            Observation(host="a", jarm=CS_JARM),
            Observation(host="b", jarm=MSF_JARM),
        ])
        camps = correlate(results)
        self.assertEqual(len(camps), 0)

    def test_two_separate_campaigns(self):
        results = _scan([
            Observation(host="a", jarm=CS_JARM),
            Observation(host="b", jarm=CS_JARM),
            Observation(host="c", jarm=MSF_JARM),
            Observation(host="d", jarm=MSF_JARM),
        ])
        camps = correlate(results)
        self.assertEqual(len(camps), 2)
        for c in camps:
            self.assertEqual(c.size, 2)

    def test_transitive_clustering_via_jarm(self):
        # a-b share jarm, b-c share jarm => all three in one campaign.
        results = _scan([
            Observation(host="a", jarm=CS_JARM),
            Observation(host="b", jarm=CS_JARM),
            Observation(host="c", jarm=CS_JARM),
        ])
        camps = correlate(results)
        self.assertEqual(len(camps), 1)
        self.assertEqual(camps[0].size, 3)

    def test_cert_serial_strongest_pivot(self):
        results = _scan([
            Observation(host="a", cert="CN=x.test serial: ABCD1234"),
            Observation(host="b", cert="CN=y.test serial: ABCD1234"),
        ])
        camps = correlate(results)
        self.assertEqual(len(camps), 1)
        self.assertIn("cert_serial", camps[0].shared)

    def test_port_alone_does_not_cluster(self):
        results = _scan([
            Observation(host="a", port=443),
            Observation(host="b", port=443),
        ])
        camps = correlate(results)
        self.assertEqual(len(camps), 0)

    def test_singletons_excluded_by_default(self):
        results = _scan([
            Observation(host="a", jarm=CS_JARM),
            Observation(host="lonely", port=80),
        ])
        camps = correlate(results)
        self.assertEqual(len(camps), 0)  # only a singleton + lonely; no pair

    def test_include_singletons_emits_lone_hosts(self):
        results = _scan([
            Observation(host="a", jarm=CS_JARM),
            Observation(host="b", jarm=CS_JARM),
            Observation(host="lonely", port=80),
        ])
        camps = correlate(results, include_singletons=True)
        sizes = sorted(c.size for c in camps)
        self.assertEqual(sizes, [1, 2])

    def test_campaign_confidence_capped_100(self):
        results = _scan([
            Observation(host="a", jarm=CS_JARM, cert="CN=x serial: AAAA"),
            Observation(host="b", jarm=CS_JARM, cert="CN=y serial: AAAA"),
        ])
        camps = correlate(results)
        self.assertLessEqual(camps[0].confidence, 100)
        self.assertGreaterEqual(camps[0].confidence, DEFAULT_CAMPAIGN_THRESHOLD)

    def test_campaign_threshold_filters(self):
        results = _scan([
            Observation(host="a", jarm=CS_JARM),
            Observation(host="b", jarm=CS_JARM),
        ])
        # Set threshold absurdly high -> no campaign reported.
        camps = correlate(results, campaign_threshold=200)
        self.assertEqual(len(camps), 0)

    def test_edge_floor_raises_requirement(self):
        # ja3 weight is 22; with floor 30 a lone shared ja3 won't link.
        ja3 = "771,4866-4867,0-23,29-23,0"
        results = _scan([
            Observation(host="a", ja3=ja3),
            Observation(host="b", ja3=ja3),
        ])
        low = correlate(results, edge_floor=20, campaign_threshold=1)
        high = correlate(results, edge_floor=30, campaign_threshold=1)
        self.assertEqual(len(low), 1)
        self.assertEqual(len(high), 0)

    def test_severity_is_worst_of_members(self):
        results = _scan([
            Observation(host="a", jarm=CS_JARM),  # critical CS
            Observation(host="b", jarm=CS_JARM),
        ])
        camps = correlate(results)
        self.assertEqual(camps[0].severity, "critical")

    def test_campaigns_sorted_strongest_first(self):
        results = _scan([
            # 3-host CS cluster
            Observation(host="a", jarm=CS_JARM),
            Observation(host="b", jarm=CS_JARM),
            Observation(host="c", jarm=CS_JARM),
            # 2-host MSF cluster
            Observation(host="d", jarm=MSF_JARM),
            Observation(host="e", jarm=MSF_JARM),
        ])
        camps = correlate(results)
        self.assertEqual(camps[0].size, 3)  # bigger cluster first
        self.assertEqual(camps[0].cid, 0)
        self.assertEqual(camps[1].cid, 1)

    def test_families_listed(self):
        results = _scan([
            Observation(host="a", jarm=CS_JARM),
            Observation(host="b", jarm=CS_JARM),
        ])
        camps = correlate(results)
        self.assertIn("Cobalt Strike", camps[0].families)

    def test_edges_carry_pivots(self):
        results = _scan([
            Observation(host="a", jarm=CS_JARM),
            Observation(host="b", jarm=CS_JARM),
        ])
        camps = correlate(results)
        a, b, pivots = camps[0].edges[0]
        self.assertTrue(pivots)
        self.assertIn("jarm", {p.klass for p in pivots})

    def test_empty_input(self):
        self.assertEqual(correlate([]), [])

    def test_single_obs_no_campaign(self):
        results = _scan([Observation(host="a", jarm=CS_JARM)])
        self.assertEqual(correlate(results), [])

    def test_correlate_observations_convenience(self):
        camps = correlate_observations([
            Observation(host="a", jarm=CS_JARM),
            Observation(host="b", jarm=CS_JARM),
        ], threshold=1)
        self.assertEqual(len(camps), 1)


# --------------------------------------------------------------------------- #
# Campaign.as_dict / serialization
# --------------------------------------------------------------------------- #
class TestSerialization(unittest.TestCase):
    def _camps(self):
        results = _scan([
            Observation(host="a", jarm=CS_JARM, cert="CN=x serial: AA"),
            Observation(host="b", jarm=CS_JARM, cert="CN=y serial: AA"),
        ])
        return correlate(results)

    def test_as_dict_round_trips_json(self):
        d = self._camps()[0].as_dict()
        s = json.dumps(d)
        back = json.loads(s)
        self.assertEqual(back["size"], 2)
        self.assertIn("hosts", back)
        self.assertIn("shared_pivots", back)

    def test_to_json_document(self):
        doc = to_json(self._camps())
        self.assertEqual(doc["mode"], "correlate")
        self.assertEqual(doc["campaign_count"], 1)
        self.assertEqual(doc["host_count"], 2)
        json.dumps(doc)  # must be serializable

    def test_to_json_empty(self):
        doc = to_json([])
        self.assertEqual(doc["campaign_count"], 0)
        self.assertEqual(doc["host_count"], 0)

    def test_edge_dict_has_weight(self):
        edges = self._camps()[0].as_dict()["edges"]
        self.assertTrue(all("weight" in e for e in edges))


# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #
class TestRenderers(unittest.TestCase):
    def _camps(self):
        results = _scan([
            Observation(host="203.0.113.1", jarm=CS_JARM),
            Observation(host="203.0.113.2", jarm=CS_JARM),
        ])
        return correlate(results)

    def test_table_mentions_campaign_and_host(self):
        txt = to_table(self._camps())
        self.assertIn("Campaign #0", txt)
        self.assertIn("203.0.113.1", txt)
        self.assertIn("jarm", txt)

    def test_table_empty_message(self):
        txt = to_table([])
        self.assertIn("no shared-infrastructure", txt)

    def test_dot_is_valid_graph_header(self):
        dot = to_dot(self._camps())
        self.assertTrue(dot.startswith("graph c2campaigns {"))
        self.assertTrue(dot.rstrip().endswith("}"))

    def test_dot_has_subgraph_and_edge(self):
        dot = to_dot(self._camps())
        self.assertIn("subgraph cluster_0", dot)
        self.assertIn("--", dot)  # an undirected edge

    def test_dot_escapes_quotes(self):
        results = _scan([
            Observation(host='a"x', jarm=CS_JARM),
            Observation(host="b", jarm=CS_JARM),
        ])
        dot = to_dot(correlate(results))
        self.assertIn('\\"', dot)

    def test_dot_empty(self):
        dot = to_dot([])
        self.assertIn("graph c2campaigns", dot)


# --------------------------------------------------------------------------- #
# CLI integration
# --------------------------------------------------------------------------- #
class TestCorrelateCLI(unittest.TestCase):
    def _run(self, argv):
        out, err = StringIO(), StringIO()
        old_o, old_e = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = main(argv)
        finally:
            sys.stdout, sys.stderr = old_o, old_e
        return code, out.getvalue(), err.getvalue()

    def test_cli_table_fixture(self):
        code, out, _ = self._run(["correlate", FIXTURE])
        self.assertEqual(code, 1)  # campaigns found
        self.assertIn("Campaign #0", out)

    def test_cli_json_fixture(self):
        code, out, _ = self._run(["correlate", FIXTURE, "--format", "json"])
        doc = json.loads(out)
        self.assertEqual(doc["mode"], "correlate")
        # CS cluster of 3 + MSF cluster of 2 = 2 campaigns
        self.assertEqual(doc["campaign_count"], 2)

    def test_cli_dot_fixture(self):
        code, out, _ = self._run(["correlate", FIXTURE, "--format", "dot"])
        self.assertIn("graph c2campaigns", out)
        self.assertIn("subgraph", out)

    def test_cli_fixture_cs_cluster_has_three(self):
        _, out, _ = self._run(["correlate", FIXTURE, "--format", "json"])
        doc = json.loads(out)
        sizes = sorted(c["size"] for c in doc["campaigns"])
        self.assertEqual(sizes, [2, 3])

    def test_cli_cert_serial_pivot_in_fixture(self):
        _, out, _ = self._run(["correlate", FIXTURE, "--format", "json"])
        doc = json.loads(out)
        cs = max(doc["campaigns"], key=lambda c: c["size"])
        self.assertIn("cert_serial", cs["shared_pivots"])

    def test_cli_fail_on_critical_gates(self):
        code, _, _ = self._run(["correlate", FIXTURE, "--fail-on", "critical"])
        self.assertEqual(code, 2)

    def test_cli_fail_on_no_match_returns_zero(self):
        # Single isolated host => no campaign => fail-on returns 0.
        out, err = StringIO(), StringIO()
        old_o, old_e = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            # stdin path: feed text that yields one observation only
            import io
            old_stdin = sys.stdin
            sys.stdin = io.StringIO("jarm: " + CS_JARM)
            try:
                code = main(["correlate", "--fail-on", "high"])
            finally:
                sys.stdin = old_stdin
        finally:
            sys.stdout, sys.stderr = old_o, old_e
        self.assertEqual(code, 0)

    def test_cli_include_singletons(self):
        _, out, _ = self._run(
            ["correlate", FIXTURE, "--include-singletons", "--format", "json"])
        doc = json.loads(out)
        # 6 hosts total: a 3-cluster, a 2-cluster, and 1 lone host
        self.assertEqual(doc["host_count"], 6)

    def test_cli_no_campaigns_exit_zero(self):
        import io
        out = StringIO()
        old_o, old_stdin = sys.stdout, sys.stdin
        sys.stdout = out
        sys.stdin = io.StringIO('{"host":"x","port":80}')
        try:
            code = main(["correlate"])
        finally:
            sys.stdout, sys.stdin = old_o, old_stdin
        self.assertEqual(code, 0)


# --------------------------------------------------------------------------- #
# MCP tool
# --------------------------------------------------------------------------- #
class TestMCPCorrelate(unittest.TestCase):
    def test_correlate_tool_dict(self):
        out = mcp_server.correlate_tool({
            "observations": [
                {"host": "a", "jarm": CS_JARM},
                {"host": "b", "jarm": CS_JARM},
            ]
        })
        self.assertEqual(out["campaign_count"], 1)

    def test_correlate_tool_json_string(self):
        payload = json.dumps([
            {"host": "a", "jarm": CS_JARM},
            {"host": "b", "jarm": CS_JARM},
        ])
        out = mcp_server.correlate_tool(payload)
        self.assertEqual(out["campaign_count"], 1)

    def test_correlate_tool_list(self):
        out = mcp_server.correlate_tool([
            {"host": "a", "jarm": MSF_JARM},
            {"host": "b", "jarm": MSF_JARM},
        ])
        self.assertEqual(out["host_count"], 2)

    def test_correlate_tool_empty(self):
        out = mcp_server.correlate_tool({})
        self.assertEqual(out["campaign_count"], 0)

    def test_correlate_listed_in_tools(self):
        # tools/list must advertise the correlate tool.
        import io
        captured = []
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        old = sys.stdout
        sys.stdout = io.StringIO()
        try:
            mcp_server._handle(msg)
            payload = sys.stdout.getvalue()
        finally:
            sys.stdout = old
        self.assertIn("correlate", payload)


if __name__ == "__main__":
    unittest.main()
