"""c2detect.active — AUTHORIZED, scope-gated active TLS probing.

================================  READ THIS  ================================
ACTIVE MODE IS OFF BY DEFAULT AND IS FOR AUTHORIZED DEFENSIVE USE ONLY.

Everywhere else in c2detect is purely passive: it reads telemetry you already
captured and never touches the network. This module is the one exception. It
opens a TLS/TCP connection to a host *you are authorized to assess* and
collects the *defensive observables* of the listening service — the server
certificate (subject / issuer / serial / not-after), the negotiated protocol
and cipher, an HTTP banner if one is offered, and a JARM-style server-TLS
fingerprint — and hands them to the SAME passive scanner used everywhere else.

It does NOT exploit, attack, brute-force, fuzz, send payloads, or take any
action against the target beyond a normal TLS handshake plus an optional
single benign HTTP HEAD/GET. It is, in effect, an authorized `openssl s_client`
that records the server's fingerprint so a defender can confirm whether a host
they own/operate (or are contracted to assess) is running a C2 team server.

To run a probe ALL of the following must hold, or the probe is refused:

  1. ``authorized=True``                — explicit "I am authorized" flag.
  2. a non-empty target **allowlist**   — every target must be in scope.
  3. a positive **rate limit**          — connections/second is capped.

A target not in the allowlist is skipped with a loud refusal. There is no way
to "probe everything"; the allowlist is mandatory and is matched exactly
(host or host:port, with CIDR support for IPs).

Standard library only.
============================================================================
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .core import Observation

# Loud banner the CLI prints before any active probe runs.
AUTHORIZED_USE_BANNER = (
    "================================================================\n"
    " c2detect ACTIVE MODE — AUTHORIZED DEFENSIVE USE ONLY\n"
    " You assert you have explicit, documented authorization to probe\n"
    " every target in scope. Active probing without authorization may\n"
    " be illegal. Targets outside the allowlist are refused. This tool\n"
    " performs a TLS handshake + optional benign HTTP HEAD only — it\n"
    " sends no payloads and takes no offensive action.\n"
    "================================================================"
)

DEFAULT_RATE_LIMIT = 2.0      # connections per second (max)
DEFAULT_TIMEOUT = 6.0         # seconds per connection
MAX_BANNER_BYTES = 4096


class ScopeError(PermissionError):
    """Raised when an active probe is attempted outside the authorized scope."""


class NotAuthorizedError(PermissionError):
    """Raised when active probing is requested without the authorized flag."""


@dataclass
class ProbeResult:
    """Outcome of a single authorized probe."""

    target: str
    host: str
    port: int
    ok: bool = False
    error: str = ""
    observation: Optional[Observation] = None
    tls_version: str = ""
    cipher: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_serial: str = ""
    cert_not_after: str = ""
    jarm: str = ""
    http_banner: str = ""

    def as_dict(self) -> dict:
        d = {
            "target": self.target, "host": self.host, "port": self.port,
            "ok": self.ok, "error": self.error,
            "tls_version": self.tls_version, "cipher": self.cipher,
            "cert_subject": self.cert_subject, "cert_issuer": self.cert_issuer,
            "cert_serial": self.cert_serial, "cert_not_after": self.cert_not_after,
            "jarm": self.jarm, "http_banner": self.http_banner,
        }
        if self.observation is not None:
            d["observation"] = self.observation.as_dict()
        return d


# --------------------------------------------------------------------------- #
# Scope enforcement
# --------------------------------------------------------------------------- #
def _split_host_port(target: str, default_port: int = 443) -> tuple[str, int]:
    """Parse ``host`` / ``host:port`` / ``[v6]:port`` into (host, port)."""
    t = target.strip()
    if t.startswith("["):  # bracketed IPv6
        end = t.find("]")
        host = t[1:end]
        rest = t[end + 1:]
        port = int(rest[1:]) if rest.startswith(":") and rest[1:] else default_port
        return host, port
    if t.count(":") == 1:
        host, _, p = t.partition(":")
        return host, (int(p) if p else default_port)
    return t, default_port


@dataclass
class Scope:
    """An authorized target allowlist with exact host / host:port / CIDR rules.

    A target is permitted iff its host matches an allowlist entry (exact host,
    or an IP inside an allowlisted CIDR) AND — when the entry pins a port — the
    port matches too. An entry without a port permits any port on that host.
    """

    entries: tuple[str, ...] = ()
    _hosts: dict = field(default_factory=dict, init=False)   # host -> set(ports)|{None}
    _cidrs: list = field(default_factory=list, init=False)   # (network, port|None)

    def __post_init__(self) -> None:
        for raw in self.entries:
            raw = raw.strip()
            if not raw:
                continue
            # CIDR (with optional :port)
            if "/" in raw:
                netpart, _, p = raw.partition(":") if raw.rfind(":") > raw.rfind("/") else (raw, "", "")
                try:
                    net = ipaddress.ip_network(netpart, strict=False)
                    self._cidrs.append((net, int(p) if p else None))
                    continue
                except ValueError:
                    pass
            host, has_port, port = self._parse_entry(raw)
            ports = self._hosts.setdefault(host.lower(), set())
            ports.add(int(port) if has_port else None)

    @staticmethod
    def _parse_entry(raw: str) -> tuple[str, bool, str]:
        if raw.startswith("["):
            end = raw.find("]")
            host = raw[1:end]
            rest = raw[end + 1:]
            if rest.startswith(":") and rest[1:]:
                return host, True, rest[1:]
            return host, False, ""
        if raw.count(":") == 1:
            h, _, p = raw.partition(":")
            return h, bool(p), p
        return raw, False, ""

    def __bool__(self) -> bool:
        return bool(self._hosts or self._cidrs)

    def permits(self, host: str, port: int) -> bool:
        host = host.strip().lower()
        if host in self._hosts:
            ports = self._hosts[host]
            if None in ports or port in ports:
                return True
        # CIDR match for IP hosts.
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None:
            for net, p in self._cidrs:
                if ip in net and (p is None or p == port):
                    return True
        return False

    @classmethod
    def from_iterable(cls, items: Iterable[str]) -> "Scope":
        return cls(entries=tuple(items))


class RateLimiter:
    """Simple monotonic-clock rate limiter (connections per second)."""

    def __init__(self, per_second: float, clock=time.monotonic, sleep=time.sleep):
        if per_second <= 0:
            raise ValueError("rate limit must be > 0 connections/second")
        self.min_interval = 1.0 / per_second
        self._clock = clock
        self._sleep = sleep
        self._last = None

    def wait(self) -> None:
        now = self._clock()
        if self._last is not None:
            elapsed = now - self._last
            if elapsed < self.min_interval:
                self._sleep(self.min_interval - elapsed)
        self._last = self._clock()


# --------------------------------------------------------------------------- #
# JARM-style fingerprint (defensive observable, not an attack)
# --------------------------------------------------------------------------- #
def jarm_like(tls_version: str, cipher: str, alpn: str = "") -> str:
    """A deterministic, JARM-spirit server-TLS fingerprint hex digest.

    This is a lightweight, dependency-free stand-in for the full 10-probe JARM:
    it hashes the negotiated TLS version + cipher (+ ALPN) into a stable hex
    string a defender can compare across hosts to spot a shared C2 estate. It
    is purely a fingerprint of the server's own handshake response — no attack.
    """
    import hashlib
    blob = f"{tls_version}|{cipher}|{alpn}".encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:30]


# --------------------------------------------------------------------------- #
# The probe
# --------------------------------------------------------------------------- #
def _make_context(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        # Suspected-C2 servers routinely use self-signed certs; for defensive
        # fingerprinting we still want the handshake to complete so we can read
        # the cert. We never *trust* it — we only record it.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _name_to_str(name) -> str:
    """Flatten an ssl getpeercert() rdn-sequence into 'k=v, k=v'."""
    parts = []
    for rdn in name or ():
        for k, v in rdn:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def probe_target(
    target: str,
    *,
    authorized: bool,
    scope: Scope,
    timeout: float = DEFAULT_TIMEOUT,
    verify: bool = False,
    http_head: bool = True,
    default_port: int = 443,
    threshold: int | None = None,
    _connector=None,
) -> ProbeResult:
    """Probe ONE authorized target and return a ProbeResult with an Observation.

    Refuses unless ``authorized`` is True and ``target`` is inside ``scope``.
    ``_connector`` is an injection seam for tests (defaults to a real TLS
    connection); production callers never pass it.
    """
    if not authorized:
        raise NotAuthorizedError(
            "active probing requires explicit authorization (--authorized); "
            "refusing.")
    if not scope:
        raise ScopeError(
            "active probing requires a non-empty target allowlist "
            "(--target-allowlist); refusing.")

    host, port = _split_host_port(target, default_port=default_port)
    if not scope.permits(host, port):
        raise ScopeError(
            f"target {host}:{port} is NOT in the authorized allowlist; "
            f"refusing to probe.")

    res = ProbeResult(target=target, host=host, port=port)
    connector = _connector or _real_connect
    try:
        info = connector(host, port, timeout=timeout, verify=verify,
                         http_head=http_head)
    except Exception as exc:  # noqa: BLE001 - report, never crash a sweep
        res.error = f"{type(exc).__name__}: {exc}"
        return res

    res.ok = True
    res.tls_version = info.get("tls_version", "")
    res.cipher = info.get("cipher", "")
    res.cert_subject = info.get("cert_subject", "")
    res.cert_issuer = info.get("cert_issuer", "")
    res.cert_serial = info.get("cert_serial", "")
    res.cert_not_after = info.get("cert_not_after", "")
    res.http_banner = info.get("http_banner", "")
    res.jarm = info.get("jarm") or jarm_like(
        res.tls_version, res.cipher, info.get("alpn", ""))

    cert_blob = " ".join(
        p for p in (res.cert_subject, res.cert_issuer, res.cert_serial) if p
    ).strip()
    obs = Observation(
        host=host, port=port, jarm=res.jarm,
        ja3s=info.get("ja3s", ""), ja4s=info.get("ja4s", ""),
        http_banner=res.http_banner, cert=cert_blob,
    )
    res.observation = obs
    return res


def _real_connect(host: str, port: int, *, timeout: float, verify: bool,
                  http_head: bool) -> dict:
    """Actual TLS connect (not exercised in CI; tests inject a fake connector)."""
    ctx = _make_context(verify)
    info: dict = {}
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host if verify else None) as tls:
            info["tls_version"] = tls.version() or ""
            ci = tls.cipher()
            info["cipher"] = ci[0] if ci else ""
            try:
                info["alpn"] = tls.selected_alpn_protocol() or ""
            except Exception:
                info["alpn"] = ""
            cert = tls.getpeercert() or {}
            if not cert:
                # CERT_NONE returns {}; fall back to binary form for serial.
                der = tls.getpeercert(binary_form=True)
                if der:
                    info["cert_serial"] = _serial_from_der(der)
            else:
                info["cert_subject"] = _name_to_str(cert.get("subject"))
                info["cert_issuer"] = _name_to_str(cert.get("issuer"))
                info["cert_serial"] = str(cert.get("serialNumber", ""))
                info["cert_not_after"] = str(cert.get("notAfter", ""))
            info["jarm"] = jarm_like(info.get("tls_version", ""),
                                     info.get("cipher", ""), info.get("alpn", ""))
            if http_head:
                try:
                    tls.settimeout(timeout)
                    tls.sendall(
                        b"HEAD / HTTP/1.0\r\nHost: " + host.encode() +
                        b"\r\nUser-Agent: c2detect-active/1.0\r\n\r\n")
                    data = tls.recv(MAX_BANNER_BYTES)
                    info["http_banner"] = _server_header(data)
                except Exception:
                    info["http_banner"] = ""
    return info


def _serial_from_der(der: bytes) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(der).hexdigest()[:32]


def _server_header(data: bytes) -> str:
    text = data.decode("latin-1", errors="replace")
    for line in text.split("\r\n"):
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()
    # Return the status line if no Server header (still a useful banner).
    return text.split("\r\n", 1)[0].strip() if text else ""


def probe_targets(
    targets: Iterable[str],
    *,
    authorized: bool,
    scope: Scope,
    rate_limit: float = DEFAULT_RATE_LIMIT,
    timeout: float = DEFAULT_TIMEOUT,
    verify: bool = False,
    http_head: bool = True,
    default_port: int = 443,
    skip_out_of_scope: bool = True,
    _connector=None,
    _limiter=None,
) -> list[ProbeResult]:
    """Probe many authorized targets under a rate limit.

    Out-of-scope targets are skipped (recorded as a refused ProbeResult) rather
    than aborting the whole sweep when ``skip_out_of_scope`` is True.
    """
    if not authorized:
        raise NotAuthorizedError(
            "active probing requires explicit authorization (--authorized).")
    if not scope:
        raise ScopeError(
            "active probing requires a non-empty target allowlist.")

    limiter = _limiter or RateLimiter(rate_limit)
    out: list[ProbeResult] = []
    for target in targets:
        host, port = _split_host_port(target, default_port=default_port)
        if not scope.permits(host, port):
            if skip_out_of_scope:
                r = ProbeResult(target=target, host=host, port=port)
                r.error = "REFUSED: target not in authorized allowlist (skipped)"
                out.append(r)
                continue
            raise ScopeError(f"target {host}:{port} not in allowlist.")
        limiter.wait()
        out.append(probe_target(
            target, authorized=authorized, scope=scope, timeout=timeout,
            verify=verify, http_head=http_head, default_port=default_port,
            _connector=_connector))
    return out
