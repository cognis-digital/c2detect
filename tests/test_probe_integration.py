"""Integration coverage for the authorized active probe (injected connector).

No real sockets: a fake connector returns canned TLS/cert observables so the
whole probe->scan path is exercised offline. Covers authorization refusal,
scope enforcement, connection-error handling, rate limiting, sweep skipping,
and that a probed CS team-server is attributed by the passive scanner.
"""

from __future__ import annotations

import pytest

from c2detect.active import (
    NotAuthorizedError,
    ProbeResult,
    RateLimiter,
    Scope,
    ScopeError,
    jarm_like,
    probe_target,
    probe_targets,
)
from c2detect.core import scan_observation

CS_JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"


def cs_connector(**override):
    """A fake connector that presents a Cobalt Strike team-server fingerprint."""
    def _c(host, port, *, timeout, verify, http_head):
        info = {
            "tls_version": "TLSv1.2",
            "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "cert_subject": "CN=Major Cobalt Strike",
            "cert_issuer": "CN=Major Cobalt Strike",
            "cert_serial": "146473198",
            "jarm": CS_JARM,
        }
        info.update(override)
        return info
    return _c


def benign_connector(host, port, *, timeout, verify, http_head):
    return {"tls_version": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256",
            "cert_subject": "CN=example.com", "http_banner": "nginx"}


def error_connector(host, port, *, timeout, verify, http_head):
    raise ConnectionRefusedError("connection refused")


_AUTH_SCOPE = Scope.from_iterable(["10.0.0.5", "10.0.0.0/24", "team.test:8443"])
_NO_SLEEP = RateLimiter(100.0, clock=lambda: 0.0, sleep=lambda s: None)


# --------------------------------------------------------------------------- #
# Authorization + scope gates
# --------------------------------------------------------------------------- #
class TestGates:
    def test_unauthorized_raises(self):
        with pytest.raises(NotAuthorizedError):
            probe_target("10.0.0.5", authorized=False, scope=_AUTH_SCOPE)

    def test_empty_scope_raises(self):
        with pytest.raises(ScopeError):
            probe_target("10.0.0.5", authorized=True, scope=Scope())

    def test_out_of_scope_raises(self):
        with pytest.raises(ScopeError):
            probe_target("8.8.8.8", authorized=True, scope=_AUTH_SCOPE,
                         _connector=cs_connector())

    def test_in_scope_exact_host(self):
        r = probe_target("10.0.0.5", authorized=True, scope=_AUTH_SCOPE,
                         _connector=cs_connector())
        assert r.ok and r.host == "10.0.0.5"

    def test_in_scope_cidr(self):
        r = probe_target("10.0.0.99", authorized=True, scope=_AUTH_SCOPE,
                         _connector=cs_connector())
        assert r.ok

    def test_pinned_port_enforced(self):
        # team.test is allowed only on :8443; default 443 must be refused.
        with pytest.raises(ScopeError):
            probe_target("team.test", authorized=True, scope=_AUTH_SCOPE,
                         _connector=cs_connector())
        r = probe_target("team.test:8443", authorized=True, scope=_AUTH_SCOPE,
                         _connector=cs_connector())
        assert r.ok and r.port == 8443


# --------------------------------------------------------------------------- #
# Probe -> observation -> scan
# --------------------------------------------------------------------------- #
class TestProbeToScan:
    def test_cs_teamserver_attributed(self):
        r = probe_target("10.0.0.5", authorized=True, scope=_AUTH_SCOPE,
                         _connector=cs_connector())
        assert r.observation is not None
        res = scan_observation(r.observation, threshold=35)
        assert res.top is not None and res.top.family == "Cobalt Strike"

    def test_cert_blob_assembled(self):
        r = probe_target("10.0.0.5", authorized=True, scope=_AUTH_SCOPE,
                         _connector=cs_connector())
        assert "Major Cobalt Strike" in r.observation.cert
        assert "146473198" in r.observation.cert

    def test_benign_host_no_match(self):
        r = probe_target("10.0.0.5", authorized=True, scope=_AUTH_SCOPE,
                         _connector=benign_connector)
        res = scan_observation(r.observation, threshold=35)
        assert res.count == 0

    def test_jarm_fallback_when_connector_omits_it(self):
        r = probe_target("10.0.0.5", authorized=True, scope=_AUTH_SCOPE,
                         _connector=cs_connector(jarm=""))
        # No jarm from the connector -> a jarm_like digest is synthesized.
        assert r.jarm == jarm_like("TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384", "")

    def test_connection_error_recorded_not_raised(self):
        r = probe_target("10.0.0.5", authorized=True, scope=_AUTH_SCOPE,
                         _connector=error_connector)
        assert r.ok is False
        assert "ConnectionRefusedError" in r.error

    def test_result_as_dict_serializable(self):
        import json
        r = probe_target("10.0.0.5", authorized=True, scope=_AUTH_SCOPE,
                         _connector=cs_connector())
        assert json.loads(json.dumps(r.as_dict()))["host"] == "10.0.0.5"


# --------------------------------------------------------------------------- #
# Sweeps
# --------------------------------------------------------------------------- #
class TestSweep:
    def test_sweep_authorized_required(self):
        with pytest.raises(NotAuthorizedError):
            probe_targets(["10.0.0.5"], authorized=False, scope=_AUTH_SCOPE)

    def test_sweep_empty_scope_raises(self):
        with pytest.raises(ScopeError):
            probe_targets(["10.0.0.5"], authorized=True, scope=Scope())

    def test_sweep_skips_out_of_scope(self):
        out = probe_targets(
            ["10.0.0.5", "8.8.8.8"], authorized=True, scope=_AUTH_SCOPE,
            _connector=cs_connector(), _limiter=_NO_SLEEP)
        assert len(out) == 2
        refused = [r for r in out if r.error.startswith("REFUSED")]
        assert len(refused) == 1 and refused[0].host == "8.8.8.8"

    def test_sweep_raises_on_out_of_scope_when_strict(self):
        with pytest.raises(ScopeError):
            probe_targets(
                ["8.8.8.8"], authorized=True, scope=_AUTH_SCOPE,
                skip_out_of_scope=False, _connector=cs_connector(),
                _limiter=_NO_SLEEP)

    def test_sweep_all_in_scope_probed(self):
        out = probe_targets(
            ["10.0.0.5", "10.0.0.6", "10.0.0.7"], authorized=True,
            scope=_AUTH_SCOPE, _connector=cs_connector(), _limiter=_NO_SLEEP)
        assert all(r.ok for r in out) and len(out) == 3


# --------------------------------------------------------------------------- #
# RateLimiter
# --------------------------------------------------------------------------- #
class TestRateLimiter:
    def test_rejects_nonpositive(self):
        with pytest.raises(ValueError):
            RateLimiter(0)
        with pytest.raises(ValueError):
            RateLimiter(-2.0)

    def test_sleeps_to_honor_interval(self):
        slept = []
        now = [0.0]
        rl = RateLimiter(2.0, clock=lambda: now[0], sleep=lambda s: slept.append(s))
        rl.wait()              # first call: no wait
        rl.wait()              # immediate second call must sleep ~0.5s
        assert slept and slept[0] == pytest.approx(0.5, abs=1e-6)

    def test_no_sleep_when_interval_elapsed(self):
        slept = []
        now = [0.0]
        rl = RateLimiter(2.0, clock=lambda: now[0], sleep=lambda s: slept.append(s))
        rl.wait()
        now[0] = 10.0          # plenty of time has passed
        rl.wait()
        assert slept == []


# --------------------------------------------------------------------------- #
# jarm_like helper
# --------------------------------------------------------------------------- #
class TestJarmLike:
    def test_deterministic(self):
        assert jarm_like("TLSv1.3", "AES") == jarm_like("TLSv1.3", "AES")

    def test_differs_on_input(self):
        assert jarm_like("TLSv1.3", "AES") != jarm_like("TLSv1.2", "AES")

    def test_alpn_changes_digest(self):
        assert jarm_like("TLSv1.3", "AES", "h2") != jarm_like("TLSv1.3", "AES", "")

    def test_hex_length(self):
        assert len(jarm_like("TLSv1.3", "AES")) == 30
