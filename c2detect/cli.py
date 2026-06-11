"""Command-line interface for C2DETECT.

Subcommands:
  scan   — scan JSON observation files / free-text telemetry / stdin / dirs
  match  — match explicit indicators passed on the command line
  db     — list the bundled C2 signature database
  mcp    — run the Model Context Protocol server (stdio JSON-RPC)

Output formats: table | json | sarif.  CI gating: --fail-on <severity>.
Defensive triage only — no network, no active capability.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional, Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    DEFAULT_THRESHOLD,
    SEVERITY_ORDER,
    Observation,
    ScanResult,
    fails_gate,
    list_signatures,
    load_records,
    observation_from_text,
    scan_observation,
    to_sarif,
)

# Files we are willing to slurp when a directory is passed to `scan`.
_TEXT_EXT = {".json", ".txt", ".log", ".jsonl", ".ndjson", ".csv", ".tsv", ".pcaplog"}


def _read_stdin() -> str:
    return sys.stdin.read()


def _sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.get(sev, 9)


def _render_scan_table(result: ScanResult) -> str:
    obs = result.observation
    lines: List[str] = []
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


def _render_db_table(rows: List[dict]) -> str:
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
    sub = parser.add_subparsers(dest="command")

    # scan — JSON observation files OR free-text telemetry OR stdin OR dirs.
    p_scan = sub.add_parser(
        "scan",
        help="Scan JSON observation files / telemetry text / dirs / stdin.",
    )
    p_scan.add_argument(
        "paths", nargs="*",
        help="Input file(s) or directory. If omitted, reads stdin.")
    p_scan.add_argument("--host", default="", help="Label for the host.")
    p_scan.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                        help=f"Min confidence to report (default {DEFAULT_THRESHOLD}).")
    p_scan.add_argument("--format", choices=("table", "json", "sarif"),
                        default="table")
    p_scan.add_argument("--fail-on", dest="fail_on",
                        choices=tuple(SEVERITY_ORDER), default=None,
                        help="Exit non-zero if a match at/above this severity "
                             "is found (CI gate).")

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
    p_match.add_argument("--format", choices=("table", "json", "sarif"),
                         default="table")
    p_match.add_argument("--fail-on", dest="fail_on",
                         choices=tuple(SEVERITY_ORDER), default=None)

    # db — list bundled signatures.
    p_db = sub.add_parser("db", help="List the bundled C2 signature database.")
    p_db.add_argument("--format", choices=("table", "json"), default="table")

    # mcp — run as an MCP server.
    sub.add_parser("mcp", help="Run the MCP server (stdio JSON-RPC).")

    return parser


def _gather_inputs(paths: Sequence[str]) -> List[str]:
    """Expand files/dirs into a list of text blobs (one per file)."""
    blobs: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for fn in sorted(files):
                    if os.path.splitext(fn)[1].lower() in _TEXT_EXT:
                        fp = os.path.join(root, fn)
                        with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                            blobs.append(fh.read())
        else:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                blobs.append(fh.read())
    return blobs


def _results_for_blob(blob: str, host: str, threshold: int) -> List[ScanResult]:
    """A blob is either a JSON observation array or free-text telemetry."""
    records = load_records(blob)
    if records is not None:
        out = []
        for rec in records:
            from .core import observation_from_record
            obs = observation_from_record(rec)
            if host and not obs.host:
                obs.host = host
            out.append(scan_observation(obs, threshold=threshold))
        return out
    obs = observation_from_text(blob, host=host)
    return [scan_observation(obs, threshold=threshold)]


def _emit(results: List[ScanResult], fmt: str, fail_on: Optional[str]) -> int:
    if fmt == "sarif":
        print(json.dumps(to_sarif(results), indent=2))
    elif fmt == "json":
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "result_count": len(results),
            "match_count": sum(r.count for r in results),
            "results": [r.as_dict() for r in results],
        }
        # Single-observation convenience: also surface top-level match fields.
        if len(results) == 1:
            payload["match_count"] = results[0].count
            payload["matches"] = [m.as_dict() for m in results[0].matches]
            payload["host"] = results[0].observation.host
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        chunks = [_render_scan_table(r) for r in results]
        print(("\n\n".join(chunks)) if chunks else "(no observations)")
        total = sum(r.count for r in results)
        print(f"\n{TOOL_NAME}: {total} C2 indicator(s) across "
              f"{len(results)} observation(s)")

    if fail_on is not None:
        return 2 if fails_gate(results, fail_on) else 0
    # Default: non-zero when any C2 match is found (pipeline signal).
    return 1 if any(r.count for r in results) else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            if args.paths:
                blobs = _gather_inputs(args.paths)
            else:
                blobs = [_read_stdin()]
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        results: List[ScanResult] = []
        for blob in blobs:
            results.extend(
                _results_for_blob(blob, args.host, args.threshold))
        if not results:
            results = [scan_observation(Observation(host=args.host),
                                        threshold=args.threshold)]
        return _emit(results, args.format, args.fail_on)

    if args.command == "match":
        obs = Observation(
            host=args.host, ja4=args.ja4, ja4s=args.ja4s, ja3=args.ja3,
            jarm=args.jarm, port=args.port, uris=list(args.uris),
            http_banner=args.banner, cert=args.cert,
        )
        result = scan_observation(obs, threshold=args.threshold)
        return _emit([result], args.format, args.fail_on)

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

    if args.command == "mcp":
        from .mcp_server import run_mcp_server
        run_mcp_server()
        return 0

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
