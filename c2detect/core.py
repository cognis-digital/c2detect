"""c2detect core — DEFENSIVE C2 fingerprinting from network observations (no attack capability).

Matches JA3/JA4/JARM hashes, ports, and HTTP/cert indicators in an observations JSON
against a curated table of public C2-framework signatures for blue-team triage.
"""
from __future__ import annotations
import json
TOOL_NAME = "c2detect"; TOOL_VERSION = "1.0.0"

# Public, well-known indicators (illustrative; extend via PRs). Defensive detection only.
SIGS = [
    {"family": "Cobalt Strike", "jarm": ["07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"],
     "ports": [50050], "http": ["/submit.php", "/__utm.gif"], "cert_cn": ["Major Cobalt Strike"]},
    {"family": "Sliver", "jarm": ["3fd21d20d00021d20741d20d41d21d3e1bcf2bf6e9d2a9d6a1f6c9b7e7a3f1"],
     "ports": [31337, 8888], "http": ["/health"], "cert_cn": []},
    {"family": "Metasploit/Meterpreter", "jarm": [], "ports": [4444, 4443],
     "http": ["/INITM", "/INITJM"], "cert_cn": []},
    {"family": "Mythic", "jarm": [], "ports": [7443], "http": ["/agent_message", "/new/"], "cert_cn": []},
    {"family": "Havoc", "jarm": [], "ports": [40056], "http": ["/havoc"], "cert_cn": []},
    {"family": "Brute Ratel", "jarm": [], "ports": [], "http": ["/admin/"], "cert_cn": ["BruteRatel"]},
]

def score(obs):
    """obs: dict with optional jarm, ja3, port, http_paths[], cert_cn. Returns ranked matches."""
    results = []
    for sig in SIGS:
        hits, reasons = 0, []
        if obs.get("jarm") and obs["jarm"] in sig["jarm"]:
            hits += 3; reasons.append("JARM match")
        if obs.get("port") in sig["ports"]:
            hits += 2; reasons.append(f"port {obs.get('port')}")
        for path in (obs.get("http_paths") or []):
            if any(h in path for h in sig["http"]):
                hits += 2; reasons.append(f"URI {path}")
        if obs.get("cert_cn") and any(c.lower() in obs["cert_cn"].lower() for c in sig["cert_cn"]):
            hits += 3; reasons.append("cert CN")
        if hits:
            conf = min(1.0, hits / 6)
            results.append({"family": sig["family"], "confidence": round(conf, 2),
                            "severity": "high" if conf >= 0.5 else "medium", "reasons": reasons})
    return sorted(results, key=lambda r: -r["confidence"])

def scan(observations):
    """observations: list of obs dicts. Returns findings."""
    out = []
    for i, obs in enumerate(observations):
        for m in score(obs):
            out.append({"index": i, "host": obs.get("host", "?"), **m})
    return out
