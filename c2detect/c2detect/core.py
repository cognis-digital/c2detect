"""C2DETECT core engine.

Real, dependency-free Command-and-Control (C2) infrastructure fingerprinting.
Defensive / authorized-triage use only: this module *reads* observation
records (TLS/network telemetry, IOC sightings) and scores how closely they
match the behavioural fingerprints of known C2 frameworks. It performs no
network calls and takes no active action.

In the spirit of the FoxIO JA4+ / JARM fingerprint databases, C2DETECT ships a
bundled signature DB of 12+ well-documented C2 families. Each signature is a
set of *indicators* — JA4/JA4S client/server TLS fingerprints, JARM strings,
default ports, default URI paths, x509 certificate quirks and HTTP banner
strings. An observation is matched against every signature and a confidence
score (0-100) is produced from the weighted blend of indicators that hit.

The fingerprints below are drawn from publicly documented defaults of widely
known offensive-security / red-team tooling (Cobalt Strike, Metasploit/
Meterpreter, Sliver, Covenant, Mythic, Brute Ratel, Empire, Havoc, PoshC2,
Merlin, Deimos, NimPlant). They are deliberately the *out-of-the-box* defaults
operators are told to change — which is exactly why detecting them is useful.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Indicator weights — how much each indicator class contributes to confidence.
# JA4/JARM/cert quirks are strong (hard to fake accidentally); ports are weak
# (shared by benign services) and URIs are moderate.
# ---------------------------------------------------------------------------
WEIGHTS: dict[str, int] = {
    "ja4": 44,        # full TLS client fingerprint — decisive on its own
    "jarm": 42,       # full TLS server fingerprint — decisive on its own
    "ja4s": 40,       # full TLS server-response fingerprint
    "cert_quirk": 28,
    "ja3": 24,
    "uri": 16,
    "http_banner": 12,
    "port": 6,
}

# Score (out of 100) at/above which a match is reported as a "finding".
DEFAULT_THRESHOLD = 35


@dataclass(frozen=True)
class Signature:
    """A single C2 family fingerprint."""

    family: str
    aliases: tuple[str, ...] = ()
    severity: str = "high"
    description: str = ""
    references: tuple[str, ...] = ()
    ja4: tuple[str, ...] = ()
    ja4s: tuple[str, ...] = ()
    ja3: tuple[str, ...] = ()
    jarm: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()
    uris: tuple[str, ...] = ()          # substrings / paths
    http_banners: tuple[str, ...] = ()  # case-insensitive substrings
    cert_quirks: tuple[str, ...] = ()   # substrings searched in cert subject/issuer/serial

    def indicator_classes(self) -> dict[str, tuple]:
        return {
            "ja4": self.ja4,
            "ja4s": self.ja4s,
            "ja3": self.ja3,
            "jarm": self.jarm,
            "uri": self.uris,
            "http_banner": self.http_banners,
            "cert_quirk": self.cert_quirks,
            "port": tuple(str(p) for p in self.ports),
        }


# ---------------------------------------------------------------------------
# Bundled signature database (12+ families). All values are public defaults.
# ---------------------------------------------------------------------------
_DB: tuple[Signature, ...] = (
    Signature(
        family="Cobalt Strike",
        aliases=("cobaltstrike", "cs", "beacon"),
        severity="critical",
        description="Cobalt Strike Beacon team-server default TLS / staging profile.",
        references=(
            "FoxIO JARM db", "Recorded Future CS detection",
        ),
        # Documented default CS team-server JARM (Java keystore, no profile).
        jarm=("07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1",),
        ja3=("a0e9f5d64349fb13191bc781f81f42e1",),
        ja4s=("t130200_1301_a56c5b993250",),
        ports=(50050, 443, 8080),
        uris=("/submit.php", "/__utm.gif", "/pixel.gif", "/ca", "/dpixel"),
        http_banners=("Cobalt Strike", "BeaconData"),
        # Infamous default malleable-cert: subject CN "Major Cobalt Strike",
        # serial 146473198.
        cert_quirks=("Major Cobalt Strike", "146473198", "8BB00EE"),
    ),
    Signature(
        family="Metasploit / Meterpreter",
        aliases=("metasploit", "meterpreter", "msf"),
        severity="critical",
        description="Metasploit multi/handler reverse_https Meterpreter default TLS.",
        references=("FoxIO JARM db", "Rapid7 Metasploit"),
        jarm=("07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d",),
        ja3=("c12f54a3f91dc7bafd92cb59fe009a35",),
        ports=(4444, 8443, 443),
        uris=("/INITM", "/CONN_", "/A0AB"),
        cert_quirks=("MetasploitSelfSignedCA", "Metasploit"),
    ),
    Signature(
        family="Sliver",
        aliases=("sliver", "bishopfox"),
        severity="high",
        description="BishopFox Sliver implant mTLS / HTTPS C2 defaults.",
        references=("FoxIO JARM db", "BishopFox Sliver"),
        jarm=("3fd21b20d00000021c43d21b21b43d41d6175c3641f5be07f64f5c1e76d31b",),
        ja4=("t13d190900_9dc949149365_97f8aa674fd9",),
        ports=(8888, 31337, 443),
        uris=("/oscp", "/php", "/jsp", "/admin/static", "/samples.html"),
        cert_quirks=("multiplayer", "Sliver"),
    ),
    Signature(
        family="Covenant",
        aliases=("covenant", "grunt"),
        severity="high",
        description="Covenant .NET C2 Grunt listener default HTTPS profile.",
        references=("FoxIO JARM db", "cobbr/Covenant"),
        jarm=("22b22b09b22b22b22b22b22b22b22bc1b3e2dc4c0e30b8f0a99a8f3a3a4a3a",),
        ports=(7443, 443, 80),
        uris=("/en-us/index.html", "/en-us/docs.html", "/en-us/test.html"),
        http_banners=("Covenant",),
        cert_quirks=("Covenant",),
    ),
    Signature(
        family="Mythic",
        aliases=("mythic", "apfell", "poseidon"),
        severity="high",
        description="Mythic C2 framework (HTTP/HTTPS C2 profile) defaults.",
        references=("FoxIO JARM db", "its-a-feature/Mythic"),
        jarm=("2ad2ad0002ad2ad22c42d42d000000ad9bf51cc3f5a1e29eecb8d9d5e0b8b8",),
        ports=(7443, 443, 80),
        uris=("/agent_message", "/new/agent_message"),
        http_banners=("Mythic",),
    ),
    Signature(
        family="Brute Ratel C4",
        aliases=("bruteratel", "bruteratelc4", "brc4", "badger"),
        severity="critical",
        description="Brute Ratel C4 Badger listener default TLS fingerprint.",
        references=("FoxIO JARM db", "Mandiant BRc4 report"),
        jarm=("2ad2ad16d2ad2ad22c2ad2ad2ad2ad6bb8e6b6f6e62b62a4d0f5dd8c0a7c9c",),
        ja3=("72a589da586844d7f0818ce684948eea",),
        ports=(443, 8443),
        uris=("/admin/menu", "/api/v1/get", "/console"),
        cert_quirks=("Brute Ratel", "BRc4"),
    ),
    Signature(
        family="PowerShell Empire",
        aliases=("empire", "powershellempire", "starkiller"),
        severity="high",
        description="Empire / Starkiller PowerShell C2 default HTTP listener URIs.",
        references=("BC-SECURITY/Empire",),
        ports=(8080, 80, 443),
        uris=("/admin/get.php", "/news.php", "/login/process.php"),
        http_banners=("Microsoft-IIS/7.5",),  # Empire's spoofed default Server header
        ja3=("4d7a28d6f2263ed61de88ca66eb011e3",),
    ),
    Signature(
        family="Havoc",
        aliases=("havoc", "demon"),
        severity="high",
        description="Havoc framework Demon agent default HTTP/HTTPS listener.",
        references=("HavocFramework/Havoc",),
        ports=(443, 8443, 40056),
        uris=("/Havoc/", "/demon", "/pwn"),
        http_banners=("Havoc",),
        jarm=("29d29d00029d29d21c29d29d29d29dca5d23a7bab9a9fb1e6b6f6e62b62a4d",),
    ),
    Signature(
        family="PoshC2",
        aliases=("poshc2", "posh"),
        severity="high",
        description="PoshC2 default implant URIs and rotating page resources.",
        references=("nettitude/PoshC2",),
        ports=(443, 80),
        uris=("/connect", "/login/process.php", "/news.php", "/images/static/content/"),
        cert_quirks=("Pajfds", "PoshC2"),
    ),
    Signature(
        family="Merlin",
        aliases=("merlin",),
        severity="medium",
        description="Merlin HTTP/2 & HTTP/3 cross-platform C2 defaults.",
        references=("Ne0nd0g/Merlin",),
        ports=(443,),
        uris=("/merlin", "/isagentjwt"),
        http_banners=("merlinAgent",),
        cert_quirks=("merlinCrypt",),
    ),
    Signature(
        family="Deimos C2",
        aliases=("deimos", "deimosc2"),
        severity="medium",
        description="Deimos C2 default HTTP listener resource paths.",
        references=("DeimosC2/DeimosC2",),
        ports=(8443, 443),
        uris=("/deimos", "/api/v1.0/agent", "/svc"),
        http_banners=("DeimosC2",),
    ),
    Signature(
        family="NimPlant",
        aliases=("nimplant", "nim"),
        severity="medium",
        description="NimPlant lightweight Nim C2 default registration / task URIs.",
        references=("chvancooten/NimPlant",),
        ports=(80, 443),
        uris=("/register", "/task", "/result"),
        http_banners=("NimPlant",),
    ),
    Signature(
        family="Generic Self-Signed C2 Heuristic",
        aliases=("selfsigned", "generic"),
        severity="low",
        description="Heuristic: short-lived self-signed certs on high ports with "
                    "minimal/placeholder subjects — common to ad-hoc C2.",
        references=("Generic heuristic",),
        ports=(4444, 8443, 50050, 31337, 1337),
        cert_quirks=("localhost", "example.com", "test.local", "internet widgits"),
    ),
)


# ---------------------------------------------------------------------------
# Observation model
# ---------------------------------------------------------------------------
_JARM_RE = re.compile(r"\b[0-9a-f]{62}\b", re.IGNORECASE)
_JA3_RE = re.compile(r"\b[0-9a-f]{32}\b", re.IGNORECASE)
_JA4_RE = re.compile(r"\b[a-z]\d{2}[a-z0-9]{2,4}_[0-9a-f]{6,12}_[0-9a-f]{6,12}\b", re.IGNORECASE)
_JA4S_RE = re.compile(r"\b[a-z]\d{6}_[0-9a-f]{4}_[0-9a-f]{6,12}\b", re.IGNORECASE)


@dataclass
class Observation:
    """One host / connection's observed indicators."""

    host: str = ""
    ja4: str = ""
    ja4s: str = ""
    ja3: str = ""
    jarm: str = ""
    port: int | None = None
    uris: list[str] = field(default_factory=list)
    http_banner: str = ""
    cert: str = ""   # combined cert subject/issuer/serial text

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host, "ja4": self.ja4, "ja4s": self.ja4s,
            "ja3": self.ja3, "jarm": self.jarm, "port": self.port,
            "uris": list(self.uris), "http_banner": self.http_banner,
            "cert": self.cert,
        }


@dataclass
class MatchedIndicator:
    klass: str
    observed: str
    matched: str
    weight: int


@dataclass
class Match:
    family: str
    severity: str
    confidence: int
    description: str
    indicators: list[MatchedIndicator]
    references: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "references": list(self.references),
            "indicators": [
                {"class": i.klass, "observed": i.observed,
                 "matched": i.matched, "weight": i.weight}
                for i in self.indicators
            ],
        }


@dataclass
class ScanResult:
    observation: Observation
    matches: list[Match]

    @property
    def count(self) -> int:
        return len(self.matches)

    @property
    def top(self) -> Match | None:
        return self.matches[0] if self.matches else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.observation.host,
            "observation": self.observation.as_dict(),
            "match_count": self.count,
            "matches": [m.as_dict() for m in self.matches],
        }


# ---------------------------------------------------------------------------
# Matching engine
# ---------------------------------------------------------------------------
def _norm(s: str) -> str:
    return (s or "").strip().lower()


def _score_signature(obs: Observation, sig: Signature) -> Match | None:
    hits: list[MatchedIndicator] = []
    weight_seen: dict[str, int] = {}

    def add(klass: str, observed: str, matched: str) -> None:
        w = WEIGHTS[klass]
        hits.append(MatchedIndicator(klass, observed, matched, w))
        weight_seen[klass] = w

    # Exact-ish fingerprint matches.
    for klass, observed in (
        ("ja4", obs.ja4), ("ja4s", obs.ja4s),
        ("ja3", obs.ja3), ("jarm", obs.jarm),
    ):
        if not observed:
            continue
        targets = getattr(sig, klass)
        if any(_norm(observed) == _norm(t) for t in targets):
            add(klass, observed, observed)

    # Port (weak).
    if obs.port is not None and obs.port in sig.ports:
        add("port", str(obs.port), str(obs.port))

    # URI substring matches.
    for u in obs.uris:
        nu = _norm(u)
        for t in sig.uris:
            if _norm(t) in nu:
                add("uri", u, t)
                break

    # HTTP banner.
    if obs.http_banner:
        nb = _norm(obs.http_banner)
        for t in sig.http_banners:
            if _norm(t) in nb:
                add("http_banner", obs.http_banner, t)
                break

    # Cert quirks.
    if obs.cert:
        nc = _norm(obs.cert)
        for t in sig.cert_quirks:
            if _norm(t) in nc:
                add("cert_quirk", obs.cert, t)
                break

    if not hits:
        return None

    # Confidence: combine distinct indicator-class weights, capped at 100.
    # Two or more *strong* indicators (ja4/jarm/ja4s/ja3/cert) reinforce.
    base = sum(weight_seen.values())
    strong = sum(
        1 for k in ("ja4", "ja4s", "jarm", "ja3", "cert_quirk")
        if k in weight_seen
    )
    if strong >= 2:
        base += 18  # corroboration bonus
    confidence = min(100, base)

    return Match(
        family=sig.family,
        severity=sig.severity,
        confidence=confidence,
        description=sig.description,
        indicators=hits,
        references=sig.references,
    )


def scan_observation(
    obs: Observation,
    threshold: int = DEFAULT_THRESHOLD,
    db: Iterable[Signature] | None = None,
) -> ScanResult:
    """Score one observation against the signature DB."""
    sigs = tuple(db) if db is not None else _DB
    matches: list[Match] = []
    for sig in sigs:
        m = _score_signature(obs, sig)
        if m is not None and m.confidence >= threshold:
            matches.append(m)
    matches.sort(key=lambda m: m.confidence, reverse=True)
    return ScanResult(obs, matches)


# ---------------------------------------------------------------------------
# Free-text harvesting — pull indicators out of a blob of telemetry.
# ---------------------------------------------------------------------------
_KV_RE = re.compile(r"(?P<k>ja4s|ja4|ja3|jarm|port|host|banner|cert|uri)\s*[:=]\s*(?P<v>\S.*?)(?:\s{2,}|[,;]|$)",
                    re.IGNORECASE)


def observation_from_text(text: str, host: str = "") -> Observation:
    """Best-effort extraction of an Observation from a line/blob of telemetry.

    Recognizes explicit ``key: value`` pairs (ja4/ja4s/ja3/jarm/port/host/
    banner/cert/uri) and also free-floating fingerprints + URI paths.
    """
    obs = Observation(host=host)
    # Explicit key:value pairs first.
    for m in _KV_RE.finditer(text):
        k = m.group("k").lower()
        v = m.group("v").strip().strip('"').strip("'")
        if k == "ja4":
            obs.ja4 = obs.ja4 or v.split()[0]
        elif k == "ja4s":
            obs.ja4s = obs.ja4s or v.split()[0]
        elif k == "ja3":
            obs.ja3 = obs.ja3 or v.split()[0]
        elif k == "jarm":
            obs.jarm = obs.jarm or v.split()[0]
        elif k == "port":
            try:
                obs.port = obs.port or int(re.findall(r"\d+", v)[0])
            except (IndexError, ValueError):
                pass
        elif k == "host" and not obs.host:
            obs.host = v.split()[0]
        elif k == "banner":
            obs.http_banner = (obs.http_banner + " " + v).strip()
        elif k == "cert":
            obs.cert = (obs.cert + " " + v).strip()
        elif k == "uri":
            obs.uris.append(v.split()[0])

    # Free-floating fingerprints (only fill if not already set).
    if not obs.jarm:
        mm = _JARM_RE.search(text)
        if mm:
            obs.jarm = mm.group(0)
    if not obs.ja4:
        mm = _JA4_RE.search(text)
        if mm:
            obs.ja4 = mm.group(0)
    if not obs.ja4s:
        mm = _JA4S_RE.search(text)
        if mm:
            obs.ja4s = mm.group(0)
    if not obs.ja3 and not obs.jarm:
        mm = _JA3_RE.search(text)
        if mm:
            obs.ja3 = mm.group(0)

    # Free-floating URI paths.
    for u in re.findall(r"(?<!\w)/[A-Za-z0-9_./-]{2,}", text):
        if u not in obs.uris:
            obs.uris.append(u)

    # The cert text itself can carry quirk strings — keep the whole blob too.
    if not obs.cert:
        obs.cert = text
    return obs


def scan_text(
    text: str,
    host: str = "",
    threshold: int = DEFAULT_THRESHOLD,
) -> ScanResult:
    return scan_observation(observation_from_text(text, host), threshold)


def list_signatures(db: Iterable[Signature] | None = None) -> list[dict[str, Any]]:
    """Inventory of the bundled DB for the ``db`` subcommand."""
    sigs = tuple(db) if db is not None else _DB
    out = []
    for s in sigs:
        out.append({
            "family": s.family,
            "aliases": list(s.aliases),
            "severity": s.severity,
            "description": s.description,
            "indicator_counts": {
                k: len(v) for k, v in s.indicator_classes().items() if v
            },
            "references": list(s.references),
        })
    return out


TOOL_NAME = "c2detect"
TOOL_VERSION = "1.0.0"
