"""Command-line interface for C2DETECT."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    DEFAULT_THRESHOLD,
    Observation,
    ScanResult,
    list_signatures,
    observation_from_text,
    scan_observation,
)


def _read_stdin() -> str:
    return sys.stdin.read()


def _sev_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(sev, 4)


def _render_scan_table(result: ScanResult) -> str:
    obs = result.observation
    lines: list[str] = []
    label = obs.host or "(unnamed host)"
    lines.append(f"host: {label}")
    fp = []
    for k in ("ja4", "ja4s", "ja3", "jarm"):
        v = getattr(obs, k)
        if v:
            fp.append(f"{k}={v}")
    if obs.port:
        fp.append(f"port={obs.port}")
    if fp:
        lines.append("  " + "  ".join(fp))
    if result.count == 0:
        lines.append("  no C2 framework matches above threshold.")
        return "\n".join(lines)

    lines.append("")
    width_f = max(6, max(len(m.family) for m in result.matches))
    header = f"  {'CONF'.rjust(4)}  {'SEV'.ljust(8)}  {'FAMILY'.ljust(width_f)}  INDICATORS"
    lines.append(header)
    lines.append("  " + "-" * (len(header) - 2))
    for m in result.matches:
        ind = ", ".join(f"{i.klass}" for i in m.indicators)
        lines.append(
            f"  {str(m.confidence).rjust(4)}  {m.severity.ljust(8)}  "
            f"{m.family.ljust(width_f)}  {ind}"
        )
    top = result.top
    if top:
        lines.append("")
        lines.append(f"  TOP: {top.family} ({top.confidence}% / {top.severity})")
        for i in top.indicators:
            lines.append(f"    - {i.klass} [+{i.weight}] matched '{i.matched}'")
    return "\n".join(lines)


def _render_db_table(rows: list[dict]) -> str:
    rows = sorted(rows, key=lambda r: (_sev_rank(r["severity"]), r["family"]))
    lines = []
    width_f = max(6, max(len(r["family"]) for r in rows))
    header = f"{'FAMILY'.ljust(width_f)}  {'SEV'.ljust(8)}  INDICATORS"
    lines.append(header)
    lines.append("-" * len(header))
    for r in rows:
        ic = ", ".join(f"{k}:{v}" for k, v in r["indicator_counts"].items())
        lines.append(f"{r['family'].ljust(width_f)}  {r['severity'].ljust(8)}  {ic}")
    lines.append("")
    lines.append(f"{len(rows)} families in bundled signature DB.")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Fingerprint-match TLS/network observations against a "
                    "bundled database of known C2 frameworks (JA4/JARM/cert/"
                    "URI/port indicators). Defensive triage only.",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan — free-text telemetry blob.
    p_scan = sub.add_parser(
        "scan", help="Scan telemetry text (files/stdin) for C2 fingerprints.",
    )
    p_scan.add_argument("paths", nargs="*",
                        help="Input file(s). If omitted, reads stdin.")
    p_scan.add_argument("--host", default="", help="Label for the host.")
    p_scan.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                        help=f"Min confidence to report (default {DEFAULT_THRESHOLD}).")
    p_scan.add_argument("--format", choices=("table", "json"), default="table")

    # match — explicit indicators on the command line.
    p_match = sub.add_parser(
        "match", help="Match explicit indicators (--ja4/--jarm/--port/...).",
    )
    p_match.add_argument("--host", default="")
    p_match.add_argument("--ja4", default="")
    p_match.add_argument("--ja4s", default="")
    p_match.add_argument("--ja3", default="")
    p_match.add_argument("--jarm", default="")
    p_match.add_argument("--port", type=int, default=None)
    p_match.add_argument("--uri", action="append", default=[], dest="uris")
    p_match.add_argument("--banner", default="")
    p_match.add_argument("--cert", default="")
    p_match.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    p_match.add_argument("--format", choices=("table", "json"), default="table")

    # db — list bundled signatures.
    p_db = sub.add_parser("db", help="List the bundled C2 signature database.")
    p_db.add_argument("--format", choices=("table", "json"), default="table")

    return parser


def _emit_scan(result: ScanResult, fmt: str) -> int:
    if fmt == "json":
        payload = result.as_dict()
        payload["tool"] = TOOL_NAME
        payload["version"] = TOOL_VERSION
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        print(_render_scan_table(result))
    # Non-zero exit when a C2 match is found (pipeline signal).
    return 1 if result.count > 0 else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            if args.paths:
                text = "\n".join(
                    open(p, "r", encoding="utf-8", errors="replace").read()
                    for p in args.paths
                )
            else:
                text = _read_stdin()
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        obs = observation_from_text(text, host=args.host)
        result = scan_observation(obs, threshold=args.threshold)
        return _emit_scan(result, args.format)

    if args.command == "match":
        obs = Observation(
            host=args.host, ja4=args.ja4, ja4s=args.ja4s, ja3=args.ja3,
            jarm=args.jarm, port=args.port, uris=list(args.uris),
            http_banner=args.banner, cert=args.cert,
        )
        result = scan_observation(obs, threshold=args.threshold)
        return _emit_scan(result, args.format)

    if args.command == "db":
        rows = list_signatures()
        if args.format == "json":
            print(json.dumps(
                {"tool": TOOL_NAME, "version": TOOL_VERSION,
                 "family_count": len(rows), "families": rows},
                indent=2, sort_keys=False,
            ))
        else:
            print(_render_db_table(rows))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
