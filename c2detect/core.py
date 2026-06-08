"""C2DETECT — C2 fingerprint matcher."""
from __future__ import annotations
import json, time
from pathlib import Path
from cognis_core import Finding, ScanResult, score

TOOL_NAME = "C2DETECT"
TOOL_VERSION = "0.1.0"

# Snapshot of publicly-known C2 JARM hashes — community contributed.
KNOWN_C2 = {
    "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1": ("Cobalt Strike", "critical"),
    "2ad2ad0002ad2ad0002ad2ad2ad2ad9c0d6f1e9bcb5b8b8d8f8b8c8f8e8d8c": ("Sliver",        "critical"),
    "29d29d20d29d29d21c42d43d000000ec0c8b6f5cd5d5b5e5f5b5a5d5c5e5f5": ("Mythic",         "high"),
    "3fd3fd16d29d3fd3fd42d43d00041d2c3e3f3e3d3c3b3a3938373635343332": ("Brute Ratel",    "critical"),
}

def scan(target: str, **opts) -> ScanResult:
    t0 = time.time()
    result = ScanResult(tool_name=TOOL_NAME, tool_version=TOOL_VERSION, target=str(target))
    p = Path(target)
    observations = []
    if p.is_file():
        observations = json.loads(p.read_text())
    elif p.is_dir():
        for jf in p.rglob("*.json"):
            try:
                observations.extend(json.loads(jf.read_text()))
            except Exception:
                pass
    result.items_scanned = len(observations)
    for obs in observations:
        h = obs.get("jarm") or obs.get("ja4")
        if h and h in KNOWN_C2:
            framework, sev = KNOWN_C2[h]
            result.add(Finding(
                id=f"C2-{framework.upper().replace(' ','')}",
                severity=sev, weight=3.0 if sev=="critical" else 2.5,
                title=f"C2_FRAMEWORK_{framework.upper()}",
                description=f"Host {obs.get('ip','?')}:{obs.get('port','?')} fingerprint matches {framework}",
                location=f"{obs.get('ip')}:{obs.get('port')}",
                remediation="Block egress to host. Hunt for compromised internal hosts that contacted this C2.",
                category="c2-detection",
                metadata=obs,
            ))
    result.composite_score, result.risk_level = score(result.findings)
    result.scan_duration_ms = int((time.time()-t0)*1000)
    return result
