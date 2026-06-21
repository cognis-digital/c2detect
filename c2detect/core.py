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

Standard library only. No third-party dependencies.
"""

from __future__ import annotations

import json
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
    "ja4x": 30,       # x509-derived JA4X cert fingerprint
    "cert_quirk": 28,
    "ja3": 24,
    "ja3s": 22,       # TLS server-hello fingerprint
    "uri": 16,
    "beacon": 22,     # periodic call-home cadence with low jitter (behavioral)
    "uri_regex": 18,  # checksum/encoded URI pattern (behavioral)
    "http_banner": 12,
    "user_agent": 10,
    "port": 6,
}

# Score (out of 100) at/above which a match is reported as a "finding".
DEFAULT_THRESHOLD = 35

# Ordered most→least severe; used for --fail-on gating and SARIF level mapping.
SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# Map our severities to SARIF result levels.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


@dataclass(frozen=True)
class Signature:
    """A single C2 family fingerprint.

    All fields are *observational*: TLS fingerprints, default ports, documented
    default URI paths/regexes, HTTP banners and cert quirks, plus a behavioral
    beacon-cadence window. No field describes how to attack anything — these are
    the out-of-the-box defaults a defender can spot.
    """

    family: str
    aliases: tuple[str, ...] = ()
    severity: str = "high"
    description: str = ""
    references: tuple[str, ...] = ()
    ja4: tuple[str, ...] = ()
    ja4s: tuple[str, ...] = ()
    ja4x: tuple[str, ...] = ()          # JA4X x509 cert fingerprints
    ja3: tuple[str, ...] = ()
    ja3s: tuple[str, ...] = ()          # JA3S server-hello fingerprints
    jarm: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()
    uris: tuple[str, ...] = ()          # substrings / paths
    uri_regexes: tuple[str, ...] = ()   # regex patterns over URIs (checksum/encoded)
    http_banners: tuple[str, ...] = ()  # case-insensitive substrings
    user_agents: tuple[str, ...] = ()   # default UA strings (substring match)
    cert_quirks: tuple[str, ...] = ()   # substrings searched in cert subject/issuer/serial
    # Behavioral: (min_seconds, max_seconds) default beacon interval window.
    beacon_interval: tuple[int, int] | None = None
    # Max jitter fraction (0..1) a default profile typically stays within.
    max_jitter: float = 0.0

    def indicator_classes(self) -> dict[str, tuple]:
        return {
            "ja4": self.ja4,
            "ja4s": self.ja4s,
            "ja4x": self.ja4x,
            "ja3": self.ja3,
            "ja3s": self.ja3s,
            "jarm": self.jarm,
            "uri": self.uris,
            "uri_regex": self.uri_regexes,
            "http_banner": self.http_banners,
            "user_agent": self.user_agents,
            "cert_quirk": self.cert_quirks,
            "beacon": (("%d-%ds" % self.beacon_interval,) if self.beacon_interval else ()),
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
        ja3s=("e35df3e00ca4ef31d42b34bebaa2f86e",),
        ports=(50050, 443, 8080),
        uris=("/submit.php", "/__utm.gif", "/pixel.gif", "/ca", "/dpixel"),
        # CS staging URIs are a 4-char path whose ASCII bytes sum to a multiple
        # of 0x100 (the documented checksum8 stager check).
        uri_regexes=(r"^/[A-Za-z0-9]{4}$",),
        http_banners=("Cobalt Strike", "BeaconData"),
        user_agents=("Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",),
        # Infamous default malleable-cert: subject CN "Major Cobalt Strike",
        # serial 146473198.
        cert_quirks=("Major Cobalt Strike", "146473198", "8BB00EE"),
        # Default Beacon sleep is 60s with 0% jitter out of the box.
        beacon_interval=(55, 65),
        max_jitter=0.10,
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
        ja4x=("000000000000_4f24da86fa62_e1e5a9e0 a0b1c2d3e4f5",),
        ports=(8888, 31337, 443),
        uris=("/oscp", "/php", "/jsp", "/admin/static", "/samples.html"),
        cert_quirks=("multiplayer", "Sliver"),
        beacon_interval=(50, 70),
        max_jitter=0.30,
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
        user_agents=("NimPlant",),
        beacon_interval=(55, 65),
        max_jitter=0.20,
    ),
    Signature(
        family="Villain",
        aliases=("villain", "hoaxshell"),
        severity="medium",
        description="Villain / HoaxShell HTTP(S) backdoor default session headers.",
        references=("t3l3machus/Villain", "t3l3machus/hoaxshell"),
        ports=(8888, 443, 80),
        uris=("/9ha8gq", "/c/", "/i/"),
        http_banners=("hoaxshell", "Villain"),
        user_agents=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) hoaxshell",),
    ),
    Signature(
        family="Caldera (MITRE)",
        aliases=("caldera", "mitre-caldera", "sandcat", "manx"),
        severity="medium",
        description="MITRE Caldera Sandcat/Manx agent default beacon endpoints.",
        references=("mitre/caldera",),
        ports=(8888, 8443, 7010, 7011, 7012),
        uris=("/beacon", "/file/download", "/file/upload", "/wesh"),
        http_banners=("Caldera",),
        beacon_interval=(50, 70),
        max_jitter=0.20,
    ),
    Signature(
        family="Pupy RAT",
        aliases=("pupy", "pupyrat"),
        severity="high",
        description="Pupy cross-platform RAT default obfsproxy/SSL transport.",
        references=("n1nj4sec/pupy",),
        ja3=("e7d705a3286e19ea42f587b344ee6865",),
        ports=(443, 8443, 1234),
        uris=("/pupy", "/init"),
        cert_quirks=("pupy", "n1nj4sec"),
    ),
    Signature(
        family="Koadic",
        aliases=("koadic", "kodiak"),
        severity="medium",
        description="Koadic COM C2 (JScript/VBScript) default stager URIs.",
        references=("zerosum0x0/koadic",),
        ports=(9999, 443, 80),
        uris=("/sodbcg", "/redandblack", "/qr"),
        user_agents=("Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",),
    ),
    Signature(
        family="SILENTTRINITY",
        aliases=("silenttrinity", "st", "stinger"),
        severity="high",
        description="SILENTTRINITY .NET/IronPython C2 default HTTP listener.",
        references=("byt3bl33d3r/SILENTTRINITY",),
        ports=(443, 8443, 80),
        uris=("/index.jsp", "/login", "/static/main.css"),
        http_banners=("SILENTTRINITY",),
        beacon_interval=(55, 65),
        max_jitter=0.30,
    ),
    Signature(
        family="Godzilla WebShell",
        aliases=("godzilla", "shiro"),
        severity="high",
        description="Godzilla webshell default AES-encrypted POST + cookie quirks.",
        references=("BeichenDream/Godzilla",),
        ports=(80, 443, 8080),
        uris=("/shell.jsp", "/cmd.aspx", "/index.php"),
        uri_regexes=(r"pass=[0-9a-f]{16}",),
        cert_quirks=("godzilla",),
    ),
    Signature(
        family="AdaptixC2",
        aliases=("adaptix", "adaptixc2"),
        severity="high",
        description="AdaptixC2 (Go teamserver / C++ Qt client) — fast-growing "
                    "2025-2026 open-source C2. Default teamserver/beacon listener "
                    "exposes branded HTTP headers and a fixed error page.",
        references=("Censys AdaptixC2 (Jun 2026)", "hunt.io AdaptixC2 hunting"),
        # Censys/hunt.io: 4321 teamserver, 43211 beacon listener, 6869/53362 seen.
        ports=(4321, 43211, 6869, 53362),
        uris=("/endpoint", "/endpoint/login", "/endpoint/connect"),
        # Strong: branded Server / version headers + the verbatim 404 body string.
        http_banners=("Server: AdaptixC2", "Adaptix-Version", "AdaptixC2",
                      "You need to enter the correct connection details."),
        # Default self-signed cert ships the OpenSSL placeholder subject (weak on
        # its own; corroborating, not decisive).
        cert_quirks=("Internet Widgits Pty Ltd",),
    ),
    Signature(
        family="Generic Beaconing Heuristic",
        aliases=("beacon-heuristic", "lowjitter"),
        severity="low",
        description="Heuristic: highly periodic call-home (low jitter, fixed "
                    "interval) to a high port — textbook implant cadence "
                    "regardless of family. Behavioral observation only.",
        references=("Generic behavioral heuristic", "MITRE T1071/T1029"),
        ports=(443, 8443, 8080, 4444, 50050, 8888),
        beacon_interval=(5, 86400),
        max_jitter=0.15,
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
    ja4x: str = ""
    ja3: str = ""
    ja3s: str = ""
    jarm: str = ""
    port: int | None = None
    uris: list[str] = field(default_factory=list)
    http_banner: str = ""
    user_agent: str = ""
    cert: str = ""   # combined cert subject/issuer/serial text
    # Behavioral: observed mean beacon interval (seconds) + jitter fraction.
    beacon_interval: float | None = None
    jitter: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host, "ja4": self.ja4, "ja4s": self.ja4s,
            "ja4x": self.ja4x, "ja3": self.ja3, "ja3s": self.ja3s,
            "jarm": self.jarm, "port": self.port,
            "uris": list(self.uris), "http_banner": self.http_banner,
            "user_agent": self.user_agent, "cert": self.cert,
            "beacon_interval": self.beacon_interval, "jitter": self.jitter,
        }


# Accepted aliases when reading a JSON observation record. Maps several common
# telemetry field names onto our canonical Observation fields so real-world
# exports (Zeek/Suricata/EDR/scan tools) load without hand-massaging.
_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "host": ("host", "ip", "ip_addr", "dest_ip", "server", "address", "addr"),
    "ja4": ("ja4",),
    "ja4s": ("ja4s",),
    "ja4x": ("ja4x",),
    "ja3": ("ja3",),
    "ja3s": ("ja3s",),
    "jarm": ("jarm",),
    "port": ("port", "dest_port", "dst_port", "server_port"),
    "http_banner": ("http_banner", "banner", "server_header", "server"),
    "user_agent": ("user_agent", "useragent", "ua", "http_user_agent"),
    "cert": ("cert", "cert_cn", "certificate", "subject", "issuer", "cert_subject"),
}
_URI_ALIASES = ("uris", "uri", "http_paths", "paths", "url", "urls")
_BEACON_ALIASES = ("beacon_interval", "interval", "sleep", "period", "cadence",
                   "mean_interval", "beacon_sec")
_JITTER_ALIASES = ("jitter", "jitter_frac", "jitter_pct", "variance")


def observation_from_record(rec: dict[str, Any]) -> Observation:
    """Build an Observation from a JSON dict, tolerating common field aliases.

    Unknown keys are ignored. ``port`` is coerced to int where possible. URI
    fields may be a single string or a list of strings.
    """
    obs = Observation()
    lower = {str(k).lower(): v for k, v in rec.items()}

    for canonical, names in _FIELD_ALIASES.items():
        for n in names:
            if n in lower and lower[n] not in (None, ""):
                val = lower[n]
                if canonical == "port":
                    try:
                        obs.port = int(val)
                    except (TypeError, ValueError):
                        m = re.findall(r"\d+", str(val))
                        if m:
                            obs.port = int(m[0])
                elif canonical in ("cert", "http_banner"):
                    # Concatenate multiple cert-ish fields into one blob.
                    cur = getattr(obs, canonical)
                    setattr(obs, canonical, (cur + " " + str(val)).strip())
                else:
                    if not getattr(obs, canonical):
                        setattr(obs, canonical, str(val))
                # keep scanning cert/banner aliases to merge, else stop
                if canonical not in ("cert", "http_banner"):
                    break

    for n in _URI_ALIASES:
        if n in lower and lower[n]:
            v = lower[n]
            if isinstance(v, str):
                obs.uris.append(v)
            elif isinstance(v, (list, tuple)):
                obs.uris.extend(str(x) for x in v if x)

    # Behavioral fields.
    for n in _BEACON_ALIASES:
        if n in lower and lower[n] not in (None, ""):
            try:
                obs.beacon_interval = float(lower[n])
                break
            except (TypeError, ValueError):
                m = re.findall(r"[\d.]+", str(lower[n]))
                if m:
                    obs.beacon_interval = float(m[0])
                    break
    for n in _JITTER_ALIASES:
        if n in lower and lower[n] not in (None, ""):
            try:
                j = float(lower[n])
            except (TypeError, ValueError):
                m = re.findall(r"[\d.]+", str(lower[n]))
                j = float(m[0]) if m else None
            if j is not None:
                # Accept either a fraction (0.1) or a percent (10) — normalize.
                obs.jitter = j / 100.0 if j > 1.0 else j
                break
    return obs


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
        ("ja4", obs.ja4), ("ja4s", obs.ja4s), ("ja4x", obs.ja4x),
        ("ja3", obs.ja3), ("ja3s", obs.ja3s), ("jarm", obs.jarm),
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

    # URI regex (behavioral pattern) matches.
    if sig.uri_regexes:
        for u in obs.uris:
            matched_pat = None
            for pat in sig.uri_regexes:
                try:
                    if re.search(pat, u, re.IGNORECASE):
                        matched_pat = pat
                        break
                except re.error:
                    continue
            if matched_pat:
                add("uri_regex", u, matched_pat)
                break

    # HTTP banner.
    if obs.http_banner:
        nb = _norm(obs.http_banner)
        for t in sig.http_banners:
            if _norm(t) in nb:
                add("http_banner", obs.http_banner, t)
                break

    # User-Agent (default UA strings).
    if obs.user_agent:
        nua = _norm(obs.user_agent)
        for t in sig.user_agents:
            if _norm(t) in nua:
                add("user_agent", obs.user_agent, t)
                break

    # Cert quirks.
    if obs.cert:
        nc = _norm(obs.cert)
        for t in sig.cert_quirks:
            if _norm(t) in nc:
                add("cert_quirk", obs.cert, t)
                break

    # Behavioral beacon cadence: observed mean interval within the family's
    # default window AND jitter at/under the family's documented ceiling.
    if sig.beacon_interval is not None and obs.beacon_interval is not None:
        lo, hi = sig.beacon_interval
        if lo <= obs.beacon_interval <= hi:
            jitter_ok = (
                obs.jitter is None
                or sig.max_jitter <= 0.0
                or obs.jitter <= sig.max_jitter + 1e-9
            )
            if jitter_ok:
                jdesc = "" if obs.jitter is None else f" j={obs.jitter:.2f}"
                add("beacon",
                    f"{obs.beacon_interval:g}s{jdesc}",
                    f"{lo}-{hi}s")

    if not hits:
        return None

    # Confidence: combine distinct indicator-class weights, capped at 100.
    # Two or more *strong* indicators (ja4/jarm/ja4s/ja3/cert) reinforce.
    base = sum(weight_seen.values())
    strong = sum(
        1 for k in ("ja4", "ja4s", "ja4x", "jarm", "ja3", "ja3s", "cert_quirk")
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


def scan_observations(
    records: Iterable[dict[str, Any]],
    threshold: int = DEFAULT_THRESHOLD,
    db: Iterable[Signature] | None = None,
) -> list[ScanResult]:
    """Score a list of JSON observation records, one ScanResult per record."""
    sigs = tuple(db) if db is not None else _DB
    return [
        scan_observation(observation_from_record(rec), threshold, sigs)
        for rec in records
    ]


# ---------------------------------------------------------------------------
# Free-text harvesting — pull indicators out of a blob of telemetry.
# ---------------------------------------------------------------------------
_KV_RE = re.compile(
    r"(?P<k>ja4x|ja4s|ja4|ja3s|ja3|jarm|port|host|banner|user[_-]?agent|ua|"
    r"cert|uri|beacon[_-]?interval|interval|sleep|jitter)"
    r"\s*[:=]\s*(?P<v>\S.*?)(?:\s{2,}|[,;]|$)",
    re.IGNORECASE)


def observation_from_text(text: str, host: str = "") -> Observation:
    """Best-effort extraction of an Observation from a line/blob of telemetry.

    Recognizes explicit ``key: value`` pairs (ja4/ja4s/ja3/jarm/port/host/
    banner/cert/uri) and also free-floating fingerprints + URI paths.
    """
    obs = Observation(host=host)
    # Explicit key:value pairs first.
    for m in _KV_RE.finditer(text):
        k = m.group("k").lower().replace("-", "_")
        v = m.group("v").strip().strip('"').strip("'")
        if k == "ja4":
            obs.ja4 = obs.ja4 or v.split()[0]
        elif k == "ja4s":
            obs.ja4s = obs.ja4s or v.split()[0]
        elif k == "ja4x":
            obs.ja4x = obs.ja4x or v
        elif k == "ja3":
            obs.ja3 = obs.ja3 or v.split()[0]
        elif k == "ja3s":
            obs.ja3s = obs.ja3s or v.split()[0]
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
        elif k in ("user_agent", "ua"):
            obs.user_agent = (obs.user_agent + " " + v).strip()
        elif k == "cert":
            obs.cert = (obs.cert + " " + v).strip()
        elif k == "uri":
            obs.uris.append(v.split()[0])
        elif k in ("beacon_interval", "interval", "sleep") and obs.beacon_interval is None:
            mm = re.findall(r"[\d.]+", v)
            if mm:
                obs.beacon_interval = float(mm[0])
        elif k == "jitter" and obs.jitter is None:
            mm = re.findall(r"[\d.]+", v)
            if mm:
                j = float(mm[0])
                obs.jitter = j / 100.0 if j > 1.0 else j

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


# ---------------------------------------------------------------------------
# Input loading — JSON observation files vs. free-text telemetry blobs.
# ---------------------------------------------------------------------------
def load_records(text: str) -> list[dict[str, Any]] | None:
    """If ``text`` is a JSON observation file, return the list of records.

    Accepts a bare list of objects, or an object with an ``observations``
    (or ``records``/``hosts``) array, or a single object. Returns ``None`` when
    the text is not parseable JSON (caller should fall back to text scanning).
    """
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for key in ("observations", "records", "hosts"):
            if isinstance(data.get(key), list):
                return [r for r in data[key] if isinstance(r, dict)]
        return [data]
    return None


def signatures() -> tuple[Signature, ...]:
    """Return the bundled signature database (full Signature objects).

    Public accessor so downstream emitters (e.g. detection-rule generation in
    :mod:`c2detect.rules`) can consume the raw indicators rather than the
    summarized inventory produced by :func:`list_signatures`.
    """
    return _DB


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


# ---------------------------------------------------------------------------
# SARIF 2.1.0 reporter
# ---------------------------------------------------------------------------
def to_sarif(results: list[ScanResult]) -> dict[str, Any]:
    """Render scan results as a SARIF 2.1.0 log (code-scanning compatible).

    One SARIF rule per C2 family that fired; one SARIF result per match, with
    the host as an artifact location and confidence in the properties bag.
    """
    rules: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for res in results:
        host = res.observation.host or "(unnamed-host)"
        for m in res.matches:
            rule_id = "C2-" + re.sub(r"[^A-Za-z0-9]+", "-", m.family).strip("-").upper()
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": re.sub(r"[^A-Za-z0-9]+", "", m.family) or "C2Family",
                    "shortDescription": {"text": f"{m.family} C2 fingerprint"},
                    "fullDescription": {"text": m.description or m.family},
                    "defaultConfiguration": {
                        "level": _SARIF_LEVEL.get(m.severity, "warning")
                    },
                    "helpUri": (m.references[0] if m.references else
                                "https://github.com/cognis-digital/c2detect"),
                    "properties": {"severity": m.severity},
                }
            indicators = ", ".join(
                f"{i.klass}={i.matched}" for i in m.indicators
            )
            sarif_results.append({
                "ruleId": rule_id,
                "level": _SARIF_LEVEL.get(m.severity, "warning"),
                "message": {
                    "text": f"{m.family} indicators on {host} "
                            f"(confidence {m.confidence}%): {indicators}"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": host},
                    }
                }],
                "properties": {
                    "confidence": m.confidence,
                    "severity": m.severity,
                    "indicators": [i.klass for i in m.indicators],
                },
            })

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": "https://github.com/cognis-digital/c2detect",
                    "rules": list(rules.values()),
                }
            },
            "results": sarif_results,
        }],
    }


def worst_severity(results: list[ScanResult]) -> str | None:
    """Return the most-severe severity string across all matches, or None."""
    worst = None
    worst_rank = 99
    for res in results:
        for m in res.matches:
            r = SEVERITY_ORDER.get(m.severity, 99)
            if r < worst_rank:
                worst_rank, worst = r, m.severity
    return worst


def fails_gate(results: list[ScanResult], fail_on: str | None) -> bool:
    """True when any match is at or above the ``fail_on`` severity floor."""
    if not fail_on:
        return False
    floor = SEVERITY_ORDER.get(fail_on, 99)
    for res in results:
        for m in res.matches:
            if SEVERITY_ORDER.get(m.severity, 99) <= floor:
                return True
    return False


# ---------------------------------------------------------------------------
# AI-assisted findings — merge an optional LLM pass into the rule results.
# DEFAULT OFF. When the --ai flag is given and the backend is reachable, AI
# findings are attached to the relevant ScanResult tagged source="ai". Rule
# findings are always source="rule"; AI findings that duplicate a rule family
# are dropped so the deterministic result is never altered when --ai is absent.
# ---------------------------------------------------------------------------
def _ai_finding_severity(item: dict[str, Any]) -> str:
    sev = str(item.get("severity", "info")).strip().lower()
    return sev if sev in SEVERITY_ORDER else "info"


def merge_ai_findings(
    result: "ScanResult",
    ai_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Dedupe AI findings against the rule matches already on ``result``.

    Returns the kept AI findings (each annotated with source="ai" and a
    ``candidate_novel`` flag). A finding is dropped when its title/evidence
    clearly names a C2 family the rule engine already reported for this host —
    the deterministic rule result stays authoritative.
    """
    rule_terms: set[str] = set()
    for m in result.matches:
        rule_terms.add(_norm(m.family))
        for tok in re.split(r"[^a-z0-9]+", _norm(m.family)):
            if len(tok) >= 4:
                rule_terms.add(tok)

    kept: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in ai_findings:
        if not isinstance(f, dict):
            continue
        title = str(f.get("title", "")).strip()
        ev = str(f.get("evidence", "")).strip()
        key = _norm(title) + "|" + _norm(ev)[:80]
        if key in seen:
            continue
        seen.add(key)
        blob = _norm(title + " " + ev + " " + str(f.get("why", "")))
        if any(t and t in blob for t in rule_terms):
            # AI is re-stating a family the rules already caught — skip.
            continue
        out = dict(f)
        out["source"] = "ai"
        out["severity"] = _ai_finding_severity(f)
        out["candidate_novel"] = bool(f.get("novel", False))
        kept.append(out)
    return kept


def fails_gate_with_ai(
    results: list["ScanResult"],
    ai_by_index: dict[int, list[dict[str, Any]]] | None,
    fail_on: str | None,
) -> bool:
    """Gate that also considers AI findings (used when --ai is active)."""
    if fails_gate(results, fail_on):
        return True
    if not fail_on or not ai_by_index:
        return False
    floor = SEVERITY_ORDER.get(fail_on, 99)
    for findings in ai_by_index.values():
        for f in findings:
            if SEVERITY_ORDER.get(_ai_finding_severity(f), 99) <= floor:
                return True
    return False


# ---------------------------------------------------------------------------
# shields.io endpoint badge
# ---------------------------------------------------------------------------
def to_badge(
    results: list["ScanResult"],
    ai_by_index: dict[int, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Render a shields.io *endpoint* JSON for a repo status badge.

    Color/message reflect the worst severity observed. Green "clean" when
    nothing matched. See https://shields.io/endpoint.
    """
    total = sum(r.count for r in results)
    ai_total = sum(len(v) for v in (ai_by_index or {}).values())
    worst = worst_severity(results)
    if ai_by_index:
        for findings in ai_by_index.values():
            for f in findings:
                s = _ai_finding_severity(f)
                if worst is None or SEVERITY_ORDER.get(s, 99) < SEVERITY_ORDER.get(worst, 99):
                    worst = s
    color_map = {
        "critical": "critical", "high": "red", "medium": "orange",
        "low": "yellow", "info": "blue",
    }
    grand = total + ai_total
    if grand == 0:
        message, color = "clean", "brightgreen"
    else:
        sev = worst or "info"
        message = f"{grand} finding{'s' if grand != 1 else ''} ({sev})"
        color = color_map.get(sev, "lightgrey")
    return {
        "schemaVersion": 1,
        "label": "c2detect",
        "message": message,
        "color": color,
    }


# ---------------------------------------------------------------------------
# Self-contained HTML report
# ---------------------------------------------------------------------------
def _esc(s: Any) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


_SEV_COLOR = {
    "critical": "#b91c1c", "high": "#dc2626", "medium": "#d97706",
    "low": "#ca8a04", "info": "#2563eb", "ai": "#7c3aed",
}


def to_html(
    results: list["ScanResult"],
    ai_by_index: dict[int, list[dict[str, Any]]] | None = None,
) -> str:
    """Render a clean, self-contained (no external assets) HTML report."""
    ai_by_index = ai_by_index or {}
    total = sum(r.count for r in results)
    ai_total = sum(len(v) for v in ai_by_index.values())
    worst = worst_severity(results) or "info"
    rows: list[str] = []
    for idx, res in enumerate(results):
        host = _esc(res.observation.host or "(unnamed host)")
        if res.count == 0 and not ai_by_index.get(idx):
            continue
        rows.append(f'<h3 class="host">{host}</h3>')
        if res.matches:
            rows.append('<table><thead><tr><th>Conf</th><th>Severity</th>'
                        '<th>Family</th><th>Indicators</th><th>Source</th>'
                        '</tr></thead><tbody>')
            for m in res.matches:
                ind = _esc(", ".join(f"{i.klass}" for i in m.indicators))
                col = _SEV_COLOR.get(m.severity, "#64748b")
                rows.append(
                    f'<tr><td>{m.confidence}%</td>'
                    f'<td><span class="pill" style="background:{col}">{_esc(m.severity)}</span></td>'
                    f'<td>{_esc(m.family)}</td><td class="ind">{ind}</td>'
                    f'<td><span class="src">rule</span></td></tr>')
            rows.append('</tbody></table>')
        for f in ai_by_index.get(idx, []):
            col = _SEV_COLOR["ai"]
            novel = ' <span class="novel">NOVEL?</span>' if f.get("candidate_novel") else ""
            rows.append(
                f'<div class="ai"><span class="pill" style="background:{col}">ai · '
                f'{_esc(f.get("severity","info"))}</span> <b>{_esc(f.get("title",""))}</b>{novel}'
                f'<div class="why">{_esc(f.get("why",""))}</div>'
                f'<pre>{_esc(f.get("evidence",""))}</pre></div>')
    body = "\n".join(rows) or "<p class='clean'>No C2 indicators found. ✓</p>"
    headcol = _SEV_COLOR.get(worst, "#16a34a") if total + ai_total else "#16a34a"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>c2detect report</title>
<style>
:root{{color-scheme:light dark}}
body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
margin:0;background:#0f172a;color:#e2e8f0}}
.wrap{{max-width:980px;margin:0 auto;padding:24px}}
header{{border-left:6px solid {headcol};padding:12px 18px;background:#1e293b;border-radius:8px}}
h1{{margin:0 0 4px;font-size:22px}} .sub{{color:#94a3b8;font-size:13px}}
.summary{{display:flex;gap:16px;margin:18px 0}}
.card{{background:#1e293b;border-radius:8px;padding:12px 18px;flex:1;text-align:center}}
.card b{{display:block;font-size:26px}}
h3.host{{margin:22px 0 6px;font-size:16px;color:#cbd5e1}}
table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden}}
th,td{{text-align:left;padding:8px 12px;border-bottom:1px solid #334155}}
th{{background:#334155;font-size:12px;text-transform:uppercase;letter-spacing:.04em}}
.pill{{color:#fff;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600}}
.ind{{color:#94a3b8;font-size:12px}} .src{{color:#64748b;font-size:12px}}
.ai{{background:#1e1b4b;border:1px solid #4338ca;border-radius:8px;padding:10px 14px;margin:8px 0}}
.ai pre{{white-space:pre-wrap;background:#0f172a;padding:8px;border-radius:6px;font-size:12px;overflow:auto}}
.why{{color:#c7d2fe;margin:6px 0}} .novel{{background:#7c3aed;color:#fff;padding:1px 6px;border-radius:4px;font-size:11px}}
.clean{{color:#4ade80;font-size:16px}}
footer{{color:#64748b;font-size:12px;margin-top:28px;text-align:center}}
</style></head><body><div class="wrap">
<header><h1>c2detect — C2 fingerprint report</h1>
<div class="sub">{_esc(TOOL_NAME)} {_esc(TOOL_VERSION)} · defensive triage · no network</div></header>
<div class="summary">
<div class="card"><b>{len(results)}</b>observations</div>
<div class="card"><b>{total}</b>rule findings</div>
<div class="card"><b>{ai_total}</b>ai findings</div>
<div class="card"><b style="color:{headcol}">{_esc(worst if total+ai_total else 'clean')}</b>worst severity</div>
</div>
{body}
<footer>Generated by <a style="color:#818cf8" href="https://github.com/cognis-digital/c2detect">c2detect</a> · Cognis Neural Suite</footer>
</div></body></html>"""


TOOL_NAME = "c2detect"
TOOL_VERSION = "1.3.0"
