"""Threat-intel export — MISP events and STIX 2.1 bundles from C2DETECT.

Defensive / authorized-triage use only. Standard library only, no network.

C2DETECT scans telemetry and clusters campaigns; this module turns those
findings — and the bundled signature database itself — into the two lingua
francas of threat-intel sharing so a defender can push C2DETECT's output
straight into a threat-intel platform, an ISAC feed, or a SOAR playbook:

* **MISP** — a MISP *event* JSON with one attribute per observed indicator
  (JA3/JA4/JARM/cert/URI/UA/IP/port), tagged with the detected C2 family and
  its ATT&CK technique, and a galaxy-style ``c2detect:family=...`` tag.
* **STIX 2.1** — a STIX *bundle* of ``indicator`` SDOs (with STIX-patterning
  expressions over ``x509-certificate`` / ``network-traffic`` / ``domain-name``
  properties), ``malware`` SDOs for each C2 family, and ``relationship``
  objects (``indicates``) tying them together, plus kill-chain phases.

Everything is deterministic given fixed inputs *except* freshly minted STIX
IDs / timestamps, which are derived (UUIDv5-style, from a namespace + seed) so
repeated runs over the same findings are byte-stable. This is pure export of
detections you already have — it describes nothing about how to operate a C2.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable

from .core import ScanResult, Match, Signature, signatures as _default_signatures

# A fixed namespace so STIX/MISP UUIDs are reproducible across runs. This is a
# constant seed, not a live/random UUID — determinism is a feature for diffing.
_NS = "c2detect.cognis-digital.stix"
_STIX_TS = "2026-06-21T00:00:00.000Z"

# ATT&CK technique per severity tier is coarse; families reuse T1071.001
# (application-layer protocol: web) as the shared C2 kill-chain phase.
_ATTACK_TECHNIQUE = "T1071.001"
_KILL_CHAIN = [{"kill_chain_name": "mitre-attack",
                "phase_name": "command-and-control"}]

# Which Observation/indicator fields map to which MISP attribute type.
_MISP_ATTR_TYPES: dict[str, str] = {
    "ja3": "ja3-fingerprint-md5",
    "ja3s": "ja3-fingerprint-md5",
    "ja4": "text",
    "ja4s": "text",
    "jarm": "jarm-fingerprint",
    "uri": "uri",
    "http_banner": "text",
    "user_agent": "user-agent",
    "cert_quirk": "text",
    "port": "port",
}


def _uuid5(seed: str) -> str:
    """Deterministic RFC-4122-shaped UUID (v5-ish) from a seed string."""
    h = hashlib.sha1((_NS + "|" + seed).encode("utf-8")).hexdigest()
    return f"{h[:8]}-{h[8:12]}-5{h[13:16]}-{h[16:20]}-{h[20:32]}"


def _slug(family: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", family.lower()).strip("-")


# --------------------------------------------------------------------------- #
# MISP
# --------------------------------------------------------------------------- #
def to_misp(
    results: Iterable[ScanResult],
    event_info: str = "C2DETECT — detected C2 infrastructure",
) -> dict[str, Any]:
    """Render scan results as a single MISP **event** JSON object.

    One MISP Attribute is emitted per matched indicator (deduped), each carrying
    the detected C2 family + ATT&CK tag. The host, when present, is added as an
    ``ip-dst``/``hostname`` attribute so the event pivots on infrastructure.
    """
    results = list(results)
    attributes: list[dict[str, Any]] = []
    tags: set[str] = set()
    seen: set[tuple[str, str]] = set()

    def _add(atype: str, value: str, comment: str, category: str) -> None:
        key = (atype, value)
        if not value or key in seen:
            return
        seen.add(key)
        attributes.append({
            "uuid": _uuid5(f"attr|{atype}|{value}"),
            "type": atype,
            "category": category,
            "value": value,
            "to_ids": atype not in ("port", "text"),
            "comment": comment,
        })

    worst = "info"
    from .core import SEVERITY_ORDER
    for res in results:
        host = res.observation.host
        if not res.matches:
            continue
        top = res.top
        if top and SEVERITY_ORDER.get(top.severity, 4) < SEVERITY_ORDER.get(worst, 4):
            worst = top.severity
        if host:
            htype = "ip-dst" if re.match(r"^\d+\.\d+\.\d+\.\d+$", host) else "hostname"
            _add(htype, host, "C2 infrastructure host (c2detect)", "Network activity")
        for m in res.matches:
            tags.add(f'c2detect:family="{_slug(m.family)}"')
            tags.add(f'misp-galaxy:mitre-attack-pattern="{_ATTACK_TECHNIQUE}"')
            fam_comment = f"{m.family} ({m.confidence}% / {m.severity})"
            for ind in m.indicators:
                atype = _MISP_ATTR_TYPES.get(ind.klass)
                if not atype:
                    continue
                cat = ("Payload delivery" if ind.klass in ("uri", "user_agent")
                       else "Network activity")
                _add(atype, ind.observed or ind.matched, fam_comment, cat)

    return {
        "Event": {
            "uuid": _uuid5("event|" + event_info),
            "info": event_info,
            "date": _STIX_TS[:10],
            "threat_level_id": {"critical": "1", "high": "1", "medium": "2",
                                "low": "3", "info": "4"}.get(worst, "4"),
            "analysis": "1",
            "distribution": "0",
            "Tag": [{"name": t} for t in sorted(tags)],
            "Attribute": attributes,
        }
    }


# --------------------------------------------------------------------------- #
# STIX 2.1
# --------------------------------------------------------------------------- #
def _sq(value: str) -> str:
    """Escape a value for a single-quoted STIX-patterning string constant.

    STIX 2.1 requires literal backslashes and single-quotes to be escaped;
    double the backslash first so it can't consume the following escape. Guards
    against a signature/indicator value that contains ``\\`` or ``'`` producing
    an unparseable pattern.
    """
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def _stix_pattern(match: Match, host: str) -> str | None:
    """Build a STIX-patterning expression from a match's indicators."""
    terms: list[str] = []
    for ind in match.indicators:
        v = _sq(ind.observed or ind.matched)
        if ind.klass == "ja3":
            terms.append(f"network-traffic:extensions.'tls-ext'.ja3 = '{v}'")
        elif ind.klass == "ja3s":
            terms.append(f"network-traffic:extensions.'tls-ext'.ja3s = '{v}'")
        elif ind.klass in ("ja4", "ja4s"):
            terms.append(f"network-traffic:extensions.'tls-ext'.{ind.klass} = '{v}'")
        elif ind.klass == "jarm":
            terms.append(f"network-traffic:extensions.'tls-ext'.jarm = '{v}'")
        elif ind.klass == "uri":
            terms.append(f"url:value LIKE '%{v}%'")
        elif ind.klass == "user_agent":
            terms.append(f"network-traffic:extensions.'http-request-ext'."
                         f"request_header.'User-Agent' = '{v}'")
        elif ind.klass == "cert_quirk":
            terms.append(f"x509-certificate:subject LIKE '%{v}%'")
        elif ind.klass == "port":
            raw = (ind.observed or ind.matched).strip()
            if raw.isdigit():  # dst_port RHS must be a bare integer literal
                terms.append(f"network-traffic:dst_port = {raw}")
    if host and re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        terms.append(f"ipv4-addr:value = '{_sq(host)}'")
    elif host:
        terms.append(f"domain-name:value = '{_sq(host)}'")
    if not terms:
        return None
    return "[" + " OR ".join(terms) + "]"


def to_stix(
    results: Iterable[ScanResult],
) -> dict[str, Any]:
    """Render scan results as a STIX 2.1 **bundle**.

    Emits: one ``malware`` SDO per detected C2 family (``is_family=true``),
    one ``indicator`` SDO per matched observation (STIX-patterning expression),
    and an ``indicates`` ``relationship`` linking each indicator to its family.
    Deterministic IDs (UUIDv5 over the finding content).
    """
    results = list(results)
    objects: list[dict[str, Any]] = []
    malware_ids: dict[str, str] = {}

    def _malware_id(family: str) -> str:
        if family not in malware_ids:
            mid = "malware--" + _uuid5("malware|" + family)
            malware_ids[family] = mid
            objects.append({
                "type": "malware",
                "spec_version": "2.1",
                "id": mid,
                "created": _STIX_TS,
                "modified": _STIX_TS,
                "name": family,
                "is_family": True,
                "malware_types": ["remote-access-trojan"],
                "kill_chain_phases": _KILL_CHAIN,
            })
        return malware_ids[family]

    sev_to_stix = {"critical": "high", "high": "high", "medium": "medium",
                   "low": "low", "info": "low"}
    for res in results:
        host = res.observation.host
        for m in res.matches:
            pattern = _stix_pattern(m, host)
            if not pattern:
                continue
            mid = _malware_id(m.family)
            iid = "indicator--" + _uuid5(f"indicator|{m.family}|{host}|{pattern}")
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": iid,
                "created": _STIX_TS,
                "modified": _STIX_TS,
                "name": f"{m.family} C2 fingerprint"
                        + (f" on {host}" if host else ""),
                "description": m.description or m.family,
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": _STIX_TS,
                "confidence": m.confidence,
                "kill_chain_phases": _KILL_CHAIN,
                "labels": [f"severity:{m.severity}",
                           f"attack:{_ATTACK_TECHNIQUE}"],
            })
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--" + _uuid5(f"rel|{iid}|{mid}"),
                "created": _STIX_TS,
                "modified": _STIX_TS,
                "relationship_type": "indicates",
                "source_ref": iid,
                "target_ref": mid,
            })

    return {
        "type": "bundle",
        "id": "bundle--" + _uuid5("bundle|" + str(len(objects))),
        "objects": objects,
    }


def signatures_to_stix(sigs: Iterable[Signature] | None = None) -> dict[str, Any]:
    """Render the whole bundled signature DB as a STIX 2.1 bundle.

    Useful as a shareable, platform-agnostic C2 fingerprint feed (no telemetry
    needed): one ``malware`` + one hash-pattern ``indicator`` per family.
    """
    sigs = tuple(sigs) if sigs is not None else _default_signatures()
    objects: list[dict[str, Any]] = []
    for s in sigs:
        terms: list[str] = []
        for v in s.jarm:
            terms.append(f"network-traffic:extensions.'tls-ext'.jarm = '{v}'")
        for v in s.ja3:
            terms.append(f"network-traffic:extensions.'tls-ext'.ja3 = '{v}'")
        for v in s.ja4:
            terms.append(f"network-traffic:extensions.'tls-ext'.ja4 = '{v}'")
        if not terms:
            continue
        mid = "malware--" + _uuid5("dbmal|" + s.family)
        objects.append({
            "type": "malware", "spec_version": "2.1", "id": mid,
            "created": _STIX_TS, "modified": _STIX_TS,
            "name": s.family, "is_family": True,
            "malware_types": ["remote-access-trojan"],
            "kill_chain_phases": _KILL_CHAIN,
        })
        iid = "indicator--" + _uuid5("dbind|" + s.family)
        pattern = "[" + " OR ".join(terms) + "]"
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": iid,
            "created": _STIX_TS, "modified": _STIX_TS,
            "name": f"{s.family} default TLS fingerprint",
            "description": s.description or s.family,
            "indicator_types": ["malicious-activity"],
            "pattern": pattern, "pattern_type": "stix",
            "valid_from": _STIX_TS,
            "labels": [f"severity:{s.severity}"],
            "kill_chain_phases": _KILL_CHAIN,
        })
        objects.append({
            "type": "relationship", "spec_version": "2.1",
            "id": "relationship--" + _uuid5("dbrel|" + s.family),
            "created": _STIX_TS, "modified": _STIX_TS,
            "relationship_type": "indicates",
            "source_ref": iid, "target_ref": mid,
        })
    return {
        "type": "bundle",
        "id": "bundle--" + _uuid5("dbbundle|" + str(len(objects))),
        "objects": objects,
    }
