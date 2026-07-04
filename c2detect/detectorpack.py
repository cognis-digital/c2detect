"""Feed-aggregation detector pack — thousands of live C2/malware detectors.

The bundled signature DB (`core._DB`) is a small set of hand-verified C2 *family*
fingerprints. This module is the other half: it aggregates real, public, keyless
threat-intel feeds into one normalized detector set, so a defender has thousands
of concrete, current indicators (IPs, JA3 hashes, URLs, domains) to match — and
can snapshot them for fully offline / air-gapped use.

Sources (all keyless, and already referenced by this project):
  * abuse.ch ThreatFox  — multi-family C2/malware IOCs   (CC0)
  * abuse.ch Feodo       — active botnet C2 IPs            (CC0)
  * abuse.ch SSLBL (JA3) — malicious TLS JA3 fingerprints  (CC0)
  * abuse.ch URLhaus     — malware distribution URLs        (CC0)

A "detector" here = one normalized indicator: {kind, value, family, source}.
Nothing here is offensive — these are blocklist/hunt indicators.
"""

from __future__ import annotations

import csv
import io
import json
import os
import urllib.request

FEEDS = {
    "threatfox": "https://threatfox.abuse.ch/export/csv/recent/",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
    "sslbl_ja3": "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_recent/",
}
THREATFOX_FULL = "https://threatfox.abuse.ch/export/csv/full/"
USER_AGENT = "c2detect-detectorpack/1.0 (+https://cognis.digital)"
_HERE = os.path.dirname(os.path.abspath(__file__))
SNAPSHOT = os.path.join(_HERE, "..", "data", "detector_snapshot.json")


def _fetch(url: str, timeout: int = 60) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _rows(text: str):
    body = "\n".join(l for l in text.splitlines() if l and not l.lstrip().startswith("#"))
    for row in csv.reader(io.StringIO(body)):
        if row:
            yield [c.strip().strip('"') for c in row]


def parse_threatfox(text: str) -> list:
    """ThreatFox recent/full CSV -> detectors. Columns include ioc_value and
    malware family; ioc types cover ip:port, domain, url, sha256, ja3."""
    out = []
    for r in _rows(text):
        if len(r) < 6:
            continue
        ioc, itype, family = r[2], r[3], r[5]
        kind = {"ip:port": "ipv4", "domain": "domain", "url": "url",
                "sha256_hash": "sha256", "md5_hash": "md5", "ja3_fingerprint": "ja3"}.get(itype, itype)
        value = ioc.split(":")[0] if kind == "ipv4" else ioc
        if value:
            out.append({"kind": kind, "value": value, "family": family or "unknown", "source": "threatfox"})
    return out


def parse_feodo(text: str) -> list:
    out = []
    for r in _rows(text):
        for tok in r:
            if tok.count(".") == 3 and tok.replace(".", "").isdigit():
                fam = r[-1] if len(r) > 1 else "feodo"
                out.append({"kind": "ipv4", "value": tok, "family": fam, "source": "feodo"})
                break
    return out


def parse_sslbl_ja3(text: str) -> list:
    out = []
    for r in _rows(text):
        for tok in r:
            if len(tok) == 32 and all(c in "0123456789abcdefABCDEF" for c in tok):
                out.append({"kind": "ja3", "value": tok.lower(),
                            "family": (r[-1] if len(r) > 2 else "malicious-tls"), "source": "sslbl"})
                break
    return out


def parse_urlhaus(text: str) -> list:
    out = []
    for r in _rows(text):
        for tok in r:
            if tok.startswith("http://") or tok.startswith("https://"):
                out.append({"kind": "url", "value": tok, "family": "malware-distribution", "source": "urlhaus"})
                break
    return out


_PARSERS = {"threatfox": parse_threatfox, "feodo": parse_feodo,
            "sslbl_ja3": parse_sslbl_ja3, "urlhaus": parse_urlhaus}


def build(offline: bool = False, full_threatfox: bool = False) -> list:
    """Aggregate all feeds into a de-duplicated detector list."""
    if offline:
        return load_snapshot()
    detectors, seen = [], set()
    for name, url in FEEDS.items():
        if name == "threatfox" and full_threatfox:
            url = THREATFOX_FULL
        try:
            for d in _PARSERS[name](_fetch(url)):
                key = (d["kind"], d["value"].lower())
                if key not in seen:
                    seen.add(key)
                    detectors.append(d)
        except Exception:
            continue
    return detectors


def stats(detectors: list) -> dict:
    from collections import Counter
    return {"total": len(detectors),
            "by_kind": dict(Counter(d["kind"] for d in detectors)),
            "by_source": dict(Counter(d["source"] for d in detectors)),
            "families": len({d["family"] for d in detectors})}


def save_snapshot(detectors: list, path: str = SNAPSHOT) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"detectors": detectors, "count": len(detectors),
                   "note": "Aggregated abuse.ch feeds (CC0). Regenerate: python -m c2detect.detectorpack build --snapshot"},
                  f, indent=1)
    return path


def load_snapshot(path: str = SNAPSHOT) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f).get("detectors", [])


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(prog="c2detect.detectorpack",
                                description="Aggregate live threat feeds into a detector pack")
    p.add_argument("action", choices=["build", "count"], nargs="?", default="count")
    p.add_argument("--offline", action="store_true", help="use bundled snapshot")
    p.add_argument("--full", action="store_true", help="ThreatFox full export (much larger)")
    p.add_argument("--snapshot", action="store_true", help="write the bundled offline snapshot")
    args = p.parse_args(argv)
    dets = build(offline=args.offline, full_threatfox=args.full)
    print(json.dumps(stats(dets), indent=2))
    if args.snapshot and not args.offline:
        print(f"[+] snapshot -> {save_snapshot(dets)}")


if __name__ == "__main__":
    main()
