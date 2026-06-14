"""Native cognis-connect emit for c2detect — forward findings to any platform.

Maps c2detect's JSON output to the canonical `Finding` and forwards it via
`cognis-connect` (STIX/TAXII, MISP, Sigma, Splunk, Elastic, Slack/Discord, webhook, or a
`/v1` brief). cognis-connect is a soft dependency:
    pip install "git+https://github.com/cognis-digital/cognis-connect.git"

Usage:
    c2detect ... --format json | c2detect-emit --to stix
    c2detect-emit --to slack --url $WEBHOOK --dry-run < findings.json
"""

from __future__ import annotations

import argparse
import json
import sys

SOURCE = "c2detect"


def map_record(rec: dict) -> dict:
    """Tool-specific mapping (fleet-contributed, validated; safe-fallback)."""
    try:
        out = dict(rec)
        if 'title' in rec:
            out['title'] = rec['title']
        if 'severity' in rec:
            out['severity'] = rec['severity']
        if 'type' in rec:
            out['type'] = rec['type']
        if 'description' in rec:
            out['description'] = rec['description']
        if 'tags' in rec:
            out['tags'] = rec['tags']
        if 'ipv4' in rec:
            out['ipv4'] = rec['ipv4']
        if 'domain' in rec:
            out['domain'] = rec['domain']
        if 'url' in rec:
            out['url'] = rec['url']
        if 'sha256' in rec:
            out['sha256'] = rec['sha256']
        if 'cve' in rec:
            out['cve'] = rec['cve']
        if 'imo' in rec:
            out['imo'] = rec['imo']
        if 'mmsi' in rec:
            out['mmsi'] = rec['mmsi']
        if 'lat' in rec:
            out['lat'] = rec['lat']
        if 'lon' in rec:
            out['lon'] = rec['lon']
        return out
    except Exception:
        return rec


def _findings(text: str):
    from cognis_connect.findings import normalize, load
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return load(text, source=SOURCE)
    if isinstance(data, dict):
        data = data.get("findings") or data.get("results") or data.get("watchlist") or [data]
    return [normalize(map_record(r), source=SOURCE) if isinstance(r, dict) else r for r in data]


def emit_main(argv=None) -> int:
    p = argparse.ArgumentParser(prog=f"{SOURCE}-emit",
                                description=f"forward {SOURCE} JSON findings to a platform via cognis-connect")
    p.add_argument("--to", required=True,
                   choices=["stix", "taxii", "misp", "sigma", "splunk", "elastic",
                            "slack", "discord", "webhook", "brief", "findings"])
    p.add_argument("input", nargs="?", default="-", help="findings JSON file (default: stdin)")
    p.add_argument("--url", default=None)
    p.add_argument("--token", default=None)
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args(argv)
    try:
        from cognis_connect import misp, notify, sigma, siem, stix, edgemesh
    except ImportError:
        print("needs cognis-connect: pip install "
              "git+https://github.com/cognis-digital/cognis-connect.git", file=sys.stderr)
        return 1
    text = sys.stdin.read() if a.input == "-" else open(a.input, encoding="utf-8").read()
    fs = _findings(text)
    try:
        if a.to == "stix":
            print(json.dumps(stix.to_bundle(fs), indent=2))
        elif a.to == "taxii":
            print(json.dumps(stix.push_taxii(fs, a.url, token=a.token, dry_run=a.dry_run), indent=2))
        elif a.to == "misp":
            print(json.dumps(misp.push(fs, a.url, a.token or "", dry_run=a.dry_run) if a.url
                             else misp.to_event(fs), indent=2))
        elif a.to == "sigma":
            print(sigma.to_rules(fs))
        elif a.to == "splunk":
            print(json.dumps(siem.send_splunk(fs, a.url, a.token or "", dry_run=a.dry_run), indent=2))
        elif a.to == "elastic":
            print(json.dumps(siem.send_elastic(fs, a.url, token=a.token, dry_run=a.dry_run), indent=2))
        elif a.to == "slack":
            print(json.dumps(notify.send_slack(fs, a.url, dry_run=a.dry_run), indent=2))
        elif a.to == "discord":
            print(json.dumps(notify.send_discord(fs, a.url, dry_run=a.dry_run), indent=2))
        elif a.to == "webhook":
            print(json.dumps(siem.send_webhook(fs, a.url, token=a.token, dry_run=a.dry_run), indent=2))
        elif a.to == "brief":
            print(edgemesh.summarize(fs, base=a.url))
        elif a.to == "findings":
            from cognis_connect.findings import dump
            print(dump(fs))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(emit_main())
