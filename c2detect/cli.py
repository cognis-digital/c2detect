"""c2detect CLI (defensive blue-team triage)."""
import argparse, json, sys
from pathlib import Path
from c2detect.core import scan, TOOL_NAME, TOOL_VERSION
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="c2detect", description="Fingerprint C2 frameworks from network observations (defensive).")
    ap.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("scan"); s.add_argument("observations"); s.add_argument("--format", choices=["table","json"], default="table")
    s.add_argument("--fail-on", choices=["high","medium"], default=None)
    a = ap.parse_args(argv)
    if a.cmd != "scan": ap.print_help(); return 0
    data = json.loads(Path(a.observations).read_text(encoding="utf-8"))
    if isinstance(data, dict): data = data.get("observations", [data])
    findings = scan(data)
    if a.format == "json": print(json.dumps(findings, indent=2))
    else:
        for f in findings: print(f"  [{f['severity'].upper()}] {f['family']:24} conf={f['confidence']} host={f['host']}  ({', '.join(f['reasons'])})")
        print(f"\n{TOOL_NAME}: {len(findings)} C2 indicator(s)")
    order = {"high": 2, "medium": 1}
    if a.fail_on and any(order.get(f["severity"],0) >= order[a.fail_on] for f in findings): return 2
    return 0
if __name__ == "__main__": sys.exit(main())
