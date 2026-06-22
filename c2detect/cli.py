"""Command-line interface for C2DETECT.

Subcommands:
  scan   — scan JSON observation files / free-text telemetry / stdin / dirs
  match  — match explicit indicators passed on the command line
  db     — list the bundled C2 signature database
  feeds  — list/update/get the live abuse.ch threat-intel feeds (edge/air-gap)
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
    fails_gate_with_ai,
    list_signatures,
    load_records,
    merge_ai_findings,
    observation_from_text,
    scan_observation,
    to_badge,
    to_html,
    to_sarif,
)

# Files we are willing to slurp when a directory is passed to `scan`.
_TEXT_EXT = {".json", ".txt", ".log", ".jsonl", ".ndjson", ".csv", ".tsv", ".pcaplog"}

_FORMATS = ("table", "json", "sarif", "html", "badge")


def _read_stdin() -> str:
    return sys.stdin.read()


def _run_ai_pass(
    blobs: List[str],
    results: List[ScanResult],
) -> dict:
    """Optional, opt-in LLM pass over the same source the scanner already saw.

    Returns ``{index: [finding,...]}`` keyed by ScanResult index. NEVER raises:
    on a disabled/unreachable backend it prints a clear note to stderr and
    returns ``{}`` so the deterministic rule findings stand alone. With ``--ai``
    absent this function is never called, keeping output byte-for-byte
    deterministic.
    """
    try:
        from .ai_backend import CognisAIBackend
    except Exception as exc:  # pragma: no cover - import guard
        print(f"note: AI backend unavailable ({exc}); using rule findings only.",
              file=sys.stderr)
        return {}

    backend = CognisAIBackend()
    if not backend.is_enabled():
        print("note: --ai requested but no backend configured "
              "(set COGNIS_AI_BACKEND or COGNIS_AI_ENDPOINT); "
              "continuing with rule findings only.", file=sys.stderr)
        return {}
    if not backend.health():
        print(f"note: --ai backend at {backend.base_url} is unreachable; "
              "continuing with rule findings only.", file=sys.stderr)
        return {}

    # The scanner processes telemetry text/JSON; feed the SAME blobs to the LLM.
    source = "\n\n".join(blobs).strip()
    if not source:
        return {}
    try:
        findings = backend.analyze_code(
            source,
            context="Telemetry / observation records under C2-infrastructure "
                    "triage. Report indicators of command-and-control beaconing, "
                    "suspicious TLS fingerprints, staging URIs or implant cadence.",
            focus="C2 / beaconing / implant indicators and novel evasions.",
        )
    except Exception as exc:  # analyze_code is contracted not to raise, belt+braces
        print(f"note: AI analysis errored ({exc}); using rule findings only.",
              file=sys.stderr)
        return {}

    if not findings or not results:
        return {}
    # Attach all AI findings to the first observation, deduped against its rules.
    # (The LLM sees the merged source, so a single bucket is the honest mapping.)
    kept = merge_ai_findings(results[0], findings)
    return {0: kept} if kept else {}


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
    p_scan.add_argument("--format", choices=_FORMATS, default="table",
                        help="table | json | sarif | html | badge")
    p_scan.add_argument("--fail-on", dest="fail_on",
                        choices=tuple(SEVERITY_ORDER), default=None,
                        help="Exit non-zero if a match at/above this severity "
                             "is found (CI gate).")
    p_scan.add_argument("--ai", action="store_true",
                        help="OPT-IN: also run the Cognis fleet LLM over the same "
                             "source and merge novel findings (off by default; "
                             "needs COGNIS_AI_BACKEND/ENDPOINT; degrades to rules "
                             "if backend is down).")
    p_scan.add_argument("--feeds", action="store_true",
                        help="Cross-reference each observation's host IP / JA3 "
                             "against the live abuse.ch Feodo-C2 + SSLBL feeds "
                             "and append known-malicious hits.")
    p_scan.add_argument("--offline", action="store_true",
                        help="With --feeds, serve cached feeds only (air-gap); "
                             "never touch the network.")

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
    p_match.add_argument("--ja4x", default="")
    p_match.add_argument("--ja3s", default="")
    p_match.add_argument("--ua", dest="user_agent", default="",
                         help="HTTP User-Agent string.")
    p_match.add_argument("--beacon-interval", dest="beacon_interval", type=float,
                         default=None, help="Observed mean beacon interval (s).")
    p_match.add_argument("--jitter", type=float, default=None,
                         help="Observed jitter fraction (0..1) or percent.")
    p_match.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    p_match.add_argument("--format", choices=_FORMATS, default="table",
                         help="table | json | sarif | html | badge")
    p_match.add_argument("--fail-on", dest="fail_on",
                         choices=tuple(SEVERITY_ORDER), default=None)
    p_match.add_argument("--ai", action="store_true",
                         help="OPT-IN LLM pass (off by default).")
    p_match.add_argument("--feeds", action="store_true",
                         help="Cross-reference host IP / JA3 against live "
                              "abuse.ch Feodo-C2 + SSLBL feeds.")
    p_match.add_argument("--offline", action="store_true",
                         help="With --feeds, serve cached feeds only (air-gap).")

    # db — list bundled signatures.
    p_db = sub.add_parser("db", help="List the bundled C2 signature database.")
    p_db.add_argument("--format", choices=("table", "json"), default="table")

    # rules — emit deployable detection rules from the signature DB.
    p_rules = sub.add_parser(
        "rules",
        help="Generate Sigma / Suricata detection rules from the signature DB.")
    p_rules.add_argument("--format", choices=("sigma", "suricata"), default="sigma")
    p_rules.add_argument("-o", "--output", help="write to file instead of stdout")

    # feeds — live abuse.ch threat-intel feeds (edge/air-gap deployable).
    p_feeds = sub.add_parser(
        "feeds",
        help="List/update/get the live abuse.ch Feodo-C2 + SSLBL threat-intel "
             "feeds c2detect consumes (keyless; cached; offline re-serve).")
    fsub = p_feeds.add_subparsers(dest="feeds_cmd")
    fsub.add_parser("list", help="List the consumed feeds + cache freshness.")
    fu = fsub.add_parser("update", help="Fetch + cache feeds (online).")
    fu.add_argument("feeds", nargs="*", help="feed id(s); default: all relevant")
    fg = fsub.add_parser("get", help="Print parsed indicators from one feed.")
    fg.add_argument("feed", help="feodo-c2 | sslbl")
    fg.add_argument("--offline", action="store_true",
                    help="Serve from cache only (air-gap); no network.")

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


def _ai_total(ai_by_index: Optional[dict]) -> int:
    return sum(len(v) for v in (ai_by_index or {}).values())


def _run_feeds_pass(
    results: List[ScanResult],
    offline: bool,
) -> dict:
    """Cross-reference each observation against the live abuse.ch feeds.

    Returns ``{index: [hit,...]}``. NEVER raises: a missing/stale cache while
    offline, or an unreachable feed while online, prints a note to stderr and
    returns ``{}`` so the deterministic rule findings stand alone.
    """
    try:
        from . import feeds as feedmod
    except Exception as exc:  # pragma: no cover - import guard
        print(f"note: feeds module unavailable ({exc}); rule findings only.",
              file=sys.stderr)
        return {}
    try:
        feodo = feedmod.feodo_c2_ips(offline=offline)
        ja3bl = feedmod.sslbl_ja3(offline=offline)
    except FileNotFoundError as exc:
        print(f"note: --feeds --offline but feeds not cached ({exc}); "
              "run `c2detect feeds update`. Continuing with rule findings only.",
              file=sys.stderr)
        return {}
    except (ConnectionError, OSError) as exc:
        print(f"note: --feeds could not fetch ({exc}); rule findings only.",
              file=sys.stderr)
        return {}
    out: dict = {}
    for i, r in enumerate(results):
        hits = feedmod.enrich_observation(r.observation, feodo=feodo, ja3bl=ja3bl)
        if hits:
            out[i] = hits
    return out


def _feed_total(feed_by_index: Optional[dict]) -> int:
    return sum(len(v) for v in (feed_by_index or {}).values())


def _emit(
    results: List[ScanResult],
    fmt: str,
    fail_on: Optional[str],
    ai_by_index: Optional[dict] = None,
    feed_by_index: Optional[dict] = None,
) -> int:
    if fmt == "badge":
        print(json.dumps(to_badge(results, ai_by_index), indent=2))
    elif fmt == "html":
        print(to_html(results, ai_by_index))
    elif fmt == "sarif":
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
        if ai_by_index:
            payload["ai_findings"] = [
                f for findings in ai_by_index.values() for f in findings
            ]
            payload["ai_finding_count"] = _ai_total(ai_by_index)
        if feed_by_index:
            payload["feed_findings"] = [
                f for hits in feed_by_index.values() for f in hits
            ]
            payload["feed_finding_count"] = _feed_total(feed_by_index)
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        chunks = [_render_scan_table(r) for r in results]
        print(("\n\n".join(chunks)) if chunks else "(no observations)")
        total = sum(r.count for r in results)
        if ai_by_index:
            print("\n  AI-assisted findings (source=ai):")
            for findings in ai_by_index.values():
                for f in findings:
                    tag = " [novel candidate]" if f.get("candidate_novel") else ""
                    print(f"    - [{f.get('severity', 'info').upper()}] "
                          f"{f.get('title', '(untitled)')}{tag}")
        if feed_by_index:
            print("\n  Threat-intel feed hits (abuse.ch Feodo-C2 / SSLBL):")
            for hits in feed_by_index.values():
                for f in hits:
                    print(f"    - [{f.get('severity', 'info').upper()}] "
                          f"({f.get('source')}) {f.get('title', '(untitled)')}")
        print(f"\n{TOOL_NAME}: {total} C2 indicator(s) across "
              f"{len(results)} observation(s)"
              + (f" + {_ai_total(ai_by_index)} AI finding(s)"
                 if ai_by_index else "")
              + (f" + {_feed_total(feed_by_index)} feed hit(s)"
                 if feed_by_index else ""))

    if fail_on is not None:
        gated = (fails_gate_with_ai(results, ai_by_index, fail_on)
                 if ai_by_index else fails_gate(results, fail_on))
        # A live-feed hit at/above the gate severity also fails the gate: a host
        # confirmed malicious by abuse.ch is at least as actionable as a rule.
        limit = SEVERITY_ORDER.get(fail_on, 9)
        for hits in (feed_by_index or {}).values():
            if any(SEVERITY_ORDER.get(h.get("severity", "info"), 9) <= limit
                   for h in hits):
                gated = True
                break
        return 2 if gated else 0
    # Default: non-zero when any C2 match (rule / AI / feed) is found.
    if any(r.count for r in results) or _ai_total(ai_by_index) \
            or _feed_total(feed_by_index):
        return 1
    return 0


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
        ai_by_index = _run_ai_pass(blobs, results) if args.ai else None
        feed_by_index = (_run_feeds_pass(results, args.offline)
                         if args.feeds else None)
        return _emit(results, args.format, args.fail_on, ai_by_index,
                     feed_by_index)

    if args.command == "match":
        obs = Observation(
            host=args.host, ja4=args.ja4, ja4s=args.ja4s, ja4x=args.ja4x,
            ja3=args.ja3, ja3s=args.ja3s, jarm=args.jarm, port=args.port,
            uris=list(args.uris), http_banner=args.banner,
            user_agent=args.user_agent, cert=args.cert,
            beacon_interval=args.beacon_interval, jitter=args.jitter,
        )
        result = scan_observation(obs, threshold=args.threshold)
        ai_by_index = None
        if args.ai:
            blob = json.dumps(obs.as_dict())
            ai_by_index = _run_ai_pass([blob], [result])
        feed_by_index = (_run_feeds_pass([result], args.offline)
                         if args.feeds else None)
        return _emit([result], args.format, args.fail_on, ai_by_index,
                     feed_by_index)

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

    if args.command == "rules":
        from .rules import generate
        text = generate(args.format)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text if text.endswith("\n") else text + "\n")
            print(f"wrote {args.format} rules to {args.output}", file=sys.stderr)
        else:
            print(text)
        return 0

    if args.command == "feeds":
        from . import feeds as feedmod
        return feedmod.run_cli(args)

    if args.command == "mcp":
        from .mcp_server import run_mcp_server
        run_mcp_server()
        return 0

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
