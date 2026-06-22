"""Tests for c2detect.active — AUTHORIZATION-GATED active probing.

Every test here is OFFLINE: it either exercises pure scope/gating logic, uses an
INJECTED fake connector, or stands up a TLS server on 127.0.0.1 (localhost).
No test ever touches a real external host.
"""

from __future__ import annotations

import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from c2detect.active import (  # noqa: E402
    AUTHORIZED_USE_BANNER,
    NotAuthorizedError,
    ProbeResult,
    RateLimiter,
    Scope,
    ScopeError,
    _server_header,
    _split_host_port,
    jarm_like,
    probe_target,
    probe_targets,
)
from c2detect.cli import main  # noqa: E402

CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"


def fake_connector(**override):
    """Return a connector callable yielding a fixed handshake dict."""
    base = {
        "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "alpn": "h2",
        "cert_subject": "CN=teamserver",
        "cert_issuer": "CN=teamserver",
        "cert_serial": "01",
        "cert_not_after": "Jan 1 00:00:00 2030 GMT",
        "http_banner": "nginx",
    }
    base.update(override)

    def _conn(host, port, **kw):
        return dict(base)

    return _conn


# --------------------------------------------------------------------------- #
# host:port parsing
# --------------------------------------------------------------------------- #
class TestSplitHostPort(unittest.TestCase):
    def test_bare_host_default_port(self):
        self.assertEqual(_split_host_port("example.com"), ("example.com", 443))

    def test_host_port(self):
        self.assertEqual(_split_host_port("example.com:8443"), ("example.com", 8443))

    def test_ipv4_port(self):
        self.assertEqual(_split_host_port("127.0.0.1:50000"), ("127.0.0.1", 50000))

    def test_ipv6_bracketed(self):
        self.assertEqual(_split_host_port("[::1]:443"), ("::1", 443))

    def test_ipv6_bracketed_no_port(self):
        self.assertEqual(_split_host_port("[2001:db8::1]"), ("2001:db8::1", 443))

    def test_custom_default_port(self):
        self.assertEqual(_split_host_port("h", default_port=8080), ("h", 8080))


# --------------------------------------------------------------------------- #
# Scope / allowlist enforcement
# --------------------------------------------------------------------------- #
class TestScope(unittest.TestCase):
    def test_empty_scope_is_falsey(self):
        self.assertFalse(Scope())
        self.assertFalse(bool(Scope.from_iterable([])))

    def test_nonempty_scope_truthy(self):
        self.assertTrue(Scope.from_iterable(["example.com"]))

    def test_host_any_port(self):
        s = Scope.from_iterable(["example.com"])
        self.assertTrue(s.permits("example.com", 443))
        self.assertTrue(s.permits("example.com", 9999))

    def test_host_pinned_port(self):
        s = Scope.from_iterable(["example.com:443"])
        self.assertTrue(s.permits("example.com", 443))
        self.assertFalse(s.permits("example.com", 8443))

    def test_unlisted_host_denied(self):
        s = Scope.from_iterable(["example.com"])
        self.assertFalse(s.permits("evil.com", 443))

    def test_case_insensitive_host(self):
        s = Scope.from_iterable(["Example.COM"])
        self.assertTrue(s.permits("example.com", 443))

    def test_cidr_match(self):
        s = Scope.from_iterable(["10.0.0.0/24"])
        self.assertTrue(s.permits("10.0.0.5", 443))
        self.assertFalse(s.permits("10.0.1.5", 443))

    def test_cidr_with_port(self):
        s = Scope.from_iterable(["10.0.0.0/24:443"])
        self.assertTrue(s.permits("10.0.0.5", 443))
        self.assertFalse(s.permits("10.0.0.5", 80))

    def test_ipv4_exact(self):
        s = Scope.from_iterable(["127.0.0.1:8443"])
        self.assertTrue(s.permits("127.0.0.1", 8443))
        self.assertFalse(s.permits("127.0.0.1", 8444))

    def test_blank_entries_ignored(self):
        s = Scope.from_iterable(["", "  ", "example.com"])
        self.assertTrue(s.permits("example.com", 443))
        self.assertFalse(s.permits("", 443))

    def test_multiple_entries(self):
        s = Scope.from_iterable(["a.com", "b.com:8443", "192.168.0.0/16"])
        self.assertTrue(s.permits("a.com", 1))
        self.assertTrue(s.permits("b.com", 8443))
        self.assertFalse(s.permits("b.com", 80))
        self.assertTrue(s.permits("192.168.5.5", 443))


# --------------------------------------------------------------------------- #
# Rate limiter
# --------------------------------------------------------------------------- #
class TestRateLimiter(unittest.TestCase):
    def test_rejects_nonpositive(self):
        with self.assertRaises(ValueError):
            RateLimiter(0)
        with self.assertRaises(ValueError):
            RateLimiter(-1)

    def test_sleeps_to_honor_interval(self):
        slept = []
        now = [0.0]
        rl = RateLimiter(2.0, clock=lambda: now[0],
                         sleep=lambda s: slept.append(s))
        rl.wait()              # first call: no sleep
        self.assertEqual(slept, [])
        now[0] = 0.1           # only 0.1s elapsed, need 0.5s
        rl.wait()
        self.assertEqual(len(slept), 1)
        self.assertAlmostEqual(slept[0], 0.4, places=6)

    def test_no_sleep_when_interval_elapsed(self):
        slept = []
        now = [0.0]
        rl = RateLimiter(2.0, clock=lambda: now[0],
                         sleep=lambda s: slept.append(s))
        rl.wait()
        now[0] = 10.0
        rl.wait()
        self.assertEqual(slept, [])


# --------------------------------------------------------------------------- #
# JARM-like fingerprint
# --------------------------------------------------------------------------- #
class TestJarmLike(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(jarm_like("TLSv1.3", "x"), jarm_like("TLSv1.3", "x"))

    def test_distinct_inputs_distinct_output(self):
        self.assertNotEqual(jarm_like("TLSv1.3", "a"), jarm_like("TLSv1.3", "b"))

    def test_hex_length(self):
        self.assertEqual(len(jarm_like("TLSv1.3", "x")), 30)
        self.assertTrue(all(c in "0123456789abcdef" for c in jarm_like("a", "b")))


# --------------------------------------------------------------------------- #
# Gating on probe_target / probe_targets
# --------------------------------------------------------------------------- #
class TestProbeGating(unittest.TestCase):
    def setUp(self):
        self.scope = Scope.from_iterable(["127.0.0.1:8443", "good.example:443"])

    def test_refuses_unauthorized(self):
        with self.assertRaises(NotAuthorizedError):
            probe_target("127.0.0.1:8443", authorized=False, scope=self.scope)

    def test_refuses_empty_scope(self):
        with self.assertRaises(ScopeError):
            probe_target("127.0.0.1:8443", authorized=True, scope=Scope())

    def test_refuses_out_of_scope_target(self):
        with self.assertRaises(ScopeError):
            probe_target("8.8.8.8:443", authorized=True, scope=self.scope)

    def test_refuses_in_scope_host_wrong_port(self):
        with self.assertRaises(ScopeError):
            probe_target("127.0.0.1:9999", authorized=True, scope=self.scope)

    def test_targets_refuses_unauthorized(self):
        with self.assertRaises(NotAuthorizedError):
            probe_targets(["127.0.0.1:8443"], authorized=False, scope=self.scope)

    def test_targets_refuses_empty_scope(self):
        with self.assertRaises(ScopeError):
            probe_targets(["127.0.0.1:8443"], authorized=True, scope=Scope())


# --------------------------------------------------------------------------- #
# Probe with an injected fake connector (no network)
# --------------------------------------------------------------------------- #
class TestProbeWithFakeConnector(unittest.TestCase):
    def setUp(self):
        self.scope = Scope.from_iterable(["127.0.0.1:8443"])

    def test_probe_builds_observation(self):
        pr = probe_target("127.0.0.1:8443", authorized=True, scope=self.scope,
                          _connector=fake_connector())
        self.assertTrue(pr.ok)
        self.assertEqual(pr.host, "127.0.0.1")
        self.assertEqual(pr.port, 8443)
        self.assertEqual(pr.tls_version, "TLSv1.3")
        self.assertIsNotNone(pr.observation)
        self.assertEqual(pr.observation.host, "127.0.0.1")
        self.assertIn("teamserver", pr.observation.cert)

    def test_probe_jarm_from_connector(self):
        pr = probe_target("127.0.0.1:8443", authorized=True, scope=self.scope,
                          _connector=fake_connector(jarm=CS_JARM))
        self.assertEqual(pr.jarm, CS_JARM)
        self.assertEqual(pr.observation.jarm, CS_JARM)

    def test_probe_synthesizes_jarm_when_missing(self):
        pr = probe_target("127.0.0.1:8443", authorized=True, scope=self.scope,
                          _connector=fake_connector())
        # connector gave no 'jarm' => jarm_like synthesized, 30 hex chars
        self.assertEqual(len(pr.jarm), 30)

    def test_probe_connector_error_is_captured(self):
        def boom(host, port, **kw):
            raise ConnectionRefusedError("nope")
        pr = probe_target("127.0.0.1:8443", authorized=True, scope=self.scope,
                          _connector=boom)
        self.assertFalse(pr.ok)
        self.assertIn("ConnectionRefusedError", pr.error)

    def test_probe_as_dict_includes_observation(self):
        pr = probe_target("127.0.0.1:8443", authorized=True, scope=self.scope,
                          _connector=fake_connector())
        d = pr.as_dict()
        self.assertIn("observation", d)
        self.assertEqual(d["target"], "127.0.0.1:8443")

    def test_cobalt_strike_jarm_scored(self):
        from c2detect import scan_observation
        pr = probe_target("127.0.0.1:8443", authorized=True, scope=self.scope,
                          _connector=fake_connector(jarm=CS_JARM))
        res = scan_observation(pr.observation)
        self.assertGreaterEqual(res.count, 1)
        self.assertEqual(res.top.family, "Cobalt Strike")


class TestProbeTargetsSweep(unittest.TestCase):
    def setUp(self):
        self.scope = Scope.from_iterable(["127.0.0.1:8443", "127.0.0.2:8443"])
        # zero-cost limiter
        self.limiter = RateLimiter(1000.0, clock=lambda: 0.0, sleep=lambda s: None)

    def test_out_of_scope_skipped_not_raised(self):
        results = probe_targets(
            ["127.0.0.1:8443", "8.8.8.8:443"],
            authorized=True, scope=self.scope,
            _connector=fake_connector(), _limiter=self.limiter)
        self.assertEqual(len(results), 2)
        refused = [r for r in results if r.error.startswith("REFUSED")]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0].target, "8.8.8.8:443")

    def test_out_of_scope_raises_when_strict(self):
        with self.assertRaises(ScopeError):
            probe_targets(["8.8.8.8:443"], authorized=True, scope=self.scope,
                          skip_out_of_scope=False, _connector=fake_connector(),
                          _limiter=self.limiter)

    def test_all_in_scope_probed(self):
        results = probe_targets(
            ["127.0.0.1:8443", "127.0.0.2:8443"],
            authorized=True, scope=self.scope,
            _connector=fake_connector(), _limiter=self.limiter)
        self.assertTrue(all(r.ok for r in results))


# --------------------------------------------------------------------------- #
# CLI gating
# --------------------------------------------------------------------------- #
class TestProbeCli(unittest.TestCase):
    def test_default_off(self):
        rc = main(["probe", "127.0.0.1:8443"])
        self.assertEqual(rc, 2)

    def test_authorized_without_allowlist_refused(self):
        rc = main(["probe", "--authorized", "127.0.0.1:8443"])
        self.assertEqual(rc, 2)

    def test_authorized_without_targets_refused(self):
        rc = main(["probe", "--authorized", "--target-allowlist", "127.0.0.1:8443"])
        self.assertEqual(rc, 2)

    def test_nonpositive_rate_limit_refused(self):
        rc = main(["probe", "--authorized", "--target-allowlist", "127.0.0.1:8443",
                   "--rate-limit", "0", "127.0.0.1:8443"])
        self.assertEqual(rc, 2)

    def test_banner_text(self):
        self.assertIn("AUTHORIZED", AUTHORIZED_USE_BANNER)
        self.assertIn("no payloads", AUTHORIZED_USE_BANNER.lower()
                      .replace("sends no payloads", "no payloads"))


# --------------------------------------------------------------------------- #
# _server_header parsing
# --------------------------------------------------------------------------- #
class TestServerHeader(unittest.TestCase):
    def test_extracts_server_header(self):
        raw = b"HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n\r\n"
        self.assertEqual(_server_header(raw), "nginx/1.25")

    def test_falls_back_to_status_line(self):
        raw = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
        self.assertEqual(_server_header(raw), "HTTP/1.1 403 Forbidden")

    def test_empty(self):
        self.assertEqual(_server_header(b""), "")


# --------------------------------------------------------------------------- #
# Live localhost TLS server (real handshake; 127.0.0.1 only).
# Skipped if openssl is unavailable to mint a fixture cert.
# --------------------------------------------------------------------------- #
def _make_self_signed(dirpath):
    crt = os.path.join(dirpath, "c.pem")
    key = os.path.join(dirpath, "k.pem")
    proc = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
         "-out", crt, "-days", "1", "-nodes",
         "-subj", "/CN=cobaltstrike-teamserver"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return None
    return crt, key


class _LocalTLSServer:
    def __init__(self, crt, key, banner=b"HTTP/1.1 200 OK\r\nServer: TestC2\r\n\r\n"):
        self.banner = banner
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(crt, key)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()

    def _serve(self):
        self.sock.settimeout(2.0)
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        try:
            tls = self.ctx.wrap_socket(conn, server_side=True)
            try:
                tls.recv(2048)
                tls.sendall(self.banner)
            except Exception:
                pass
            tls.close()
        except Exception:
            pass

    def stop(self):
        try:
            self.sock.close()
        except Exception:
            pass


@unittest.skipUnless(shutil.which("openssl"), "openssl needed to mint fixture cert")
class TestLiveLocalhostProbe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="c2d-tls-")
        made = _make_self_signed(cls.dir)
        if not made:
            raise unittest.SkipTest("openssl could not mint a cert")
        cls.crt, cls.key = made

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_real_handshake_against_localhost(self):
        srv = _LocalTLSServer(self.crt, self.key)
        srv.start()
        try:
            scope = Scope.from_iterable([f"127.0.0.1:{srv.port}"])
            pr = probe_target(f"127.0.0.1:{srv.port}", authorized=True,
                              scope=scope, timeout=4.0, verify=False)
            self.assertTrue(pr.ok, pr.error)
            self.assertTrue(pr.tls_version.startswith("TLS"))
            self.assertTrue(pr.jarm)
            self.assertIsNotNone(pr.observation)
        finally:
            srv.stop()

    def test_out_of_scope_localhost_refused_live(self):
        srv = _LocalTLSServer(self.crt, self.key)
        srv.start()
        try:
            scope = Scope.from_iterable(["127.0.0.1:1"])  # wrong port
            with self.assertRaises(ScopeError):
                probe_target(f"127.0.0.1:{srv.port}", authorized=True,
                             scope=scope, timeout=2.0)
        finally:
            srv.stop()

    def test_cli_probe_json_against_localhost(self):
        import json as _json
        srv = _LocalTLSServer(self.crt, self.key)
        srv.start()
        try:
            target = f"127.0.0.1:{srv.port}"
            env = dict(os.environ, PYTHONPATH=os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))))
            proc = subprocess.run(
                [sys.executable, "-m", "c2detect", "probe", "--authorized",
                 "--target-allowlist", target, "--rate-limit", "50",
                 "--timeout", "4", "--format", "json", target],
                capture_output=True, text=True, env=env,
            )
            # banner goes to stderr; stdout is the JSON scan payload
            self.assertIn("AUTHORIZED", proc.stderr)
            data = _json.loads(proc.stdout)
            self.assertEqual(data["tool"], "c2detect")
            self.assertEqual(data["host"], "127.0.0.1")
        finally:
            srv.stop()

    def test_cli_probe_refuses_out_of_scope_live(self):
        srv = _LocalTLSServer(self.crt, self.key)
        srv.start()
        try:
            target = f"127.0.0.1:{srv.port}"
            env = dict(os.environ, PYTHONPATH=os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))))
            # allowlist a DIFFERENT host; the in-scope check must refuse.
            proc = subprocess.run(
                [sys.executable, "-m", "c2detect", "probe", "--authorized",
                 "--target-allowlist", "10.0.0.1:443", "--rate-limit", "50",
                 target],
                capture_output=True, text=True, env=env,
            )
            self.assertIn("refused", (proc.stderr + proc.stdout).lower())
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()
