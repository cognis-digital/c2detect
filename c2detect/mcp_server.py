"""C2DETECT MCP server — exposes C2 fingerprinting as an MCP tool.

Primary path: if the shared ``cognis_core.mcp`` helper is installed (the
Cognis Neural Suite monorepo), wire the scan function into it.

Fallback path (default, stdlib-only): a self-contained Model Context Protocol
server speaking JSON-RPC 2.0 over stdio — ``initialize``, ``tools/list`` and
``tools/call`` — so the tool runs as an MCP capability with zero third-party
dependencies. This is what ``c2detect mcp`` launches.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from .core import (
    TOOL_NAME,
    TOOL_VERSION,
    Observation,
    list_signatures,
    load_records,
    observation_from_record,
    observation_from_text,
    scan_observation,
)

_DESCRIPTION = (
    "C2 server fingerprinter — Cobalt Strike, Sliver, Mythic, Havoc, Brute "
    "Ratel and 7+ more. Match TLS/network observations (JA4/JARM/cert/URI/"
    "port) against a bundled signature DB. Defensive triage only."
)

_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "text": {"type": "string",
                 "description": "Free-text telemetry blob to harvest indicators from."},
        "observations": {
            "type": "array",
            "items": {"type": "object"},
            "description": "List of observation records (host/jarm/ja4/port/uris/cert/banner).",
        },
        "threshold": {"type": "integer",
                      "description": "Minimum confidence (0-100) to report. Default 35."},
    },
    "additionalProperties": True,
}


def _coerce_threshold(value: Any, default: int = 35) -> int:
    """Coerce an MCP-supplied threshold to an int, honoring an explicit 0.

    A bare ``x or default`` would silently turn a deliberate ``threshold: 0``
    (report everything) into the default 35 because 0 is falsy. Distinguish a
    missing/None/unparseable value (use the default) from a real 0.
    """
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def scan(payload: Any) -> dict[str, Any]:
    """Tool entry point. Accepts a dict / JSON string / free text and returns
    a JSON-able findings document."""
    threshold = 35
    results = []

    if isinstance(payload, str):
        recs = load_records(payload)
        if recs is not None:
            for rec in recs:
                results.append(scan_observation(observation_from_record(rec), threshold))
        else:
            results.append(scan_observation(observation_from_text(payload), threshold))
    elif isinstance(payload, dict):
        threshold = _coerce_threshold(payload.get("threshold"))
        if isinstance(payload.get("observations"), list):
            for rec in payload["observations"]:
                if isinstance(rec, dict):
                    results.append(
                        scan_observation(observation_from_record(rec), threshold))
        if isinstance(payload.get("text"), str) and payload["text"].strip():
            results.append(
                scan_observation(observation_from_text(payload["text"]), threshold))
        if not results:
            # Treat the dict itself as a single observation record.
            results.append(
                scan_observation(observation_from_record(payload), threshold))
    else:
        results.append(scan_observation(Observation(), threshold))

    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "match_count": sum(r.count for r in results),
        "results": [r.as_dict() for r in results],
    }


def correlate_tool(payload: Any) -> dict[str, Any]:
    """MCP tool: cluster many observations into shared-infrastructure campaigns.

    Accepts the same shapes as ``scan`` (a JSON string, a dict with an
    ``observations`` list, or a bare list). Returns the correlation document.
    """
    from .correlate import correlate, to_json

    threshold = 35
    recs: list[dict] = []
    if isinstance(payload, str):
        loaded = load_records(payload)
        recs = loaded or []
    elif isinstance(payload, list):
        recs = [r for r in payload if isinstance(r, dict)]
    elif isinstance(payload, dict):
        threshold = _coerce_threshold(payload.get("threshold"))
        if isinstance(payload.get("observations"), list):
            recs = [r for r in payload["observations"] if isinstance(r, dict)]
        elif "host" in payload or "jarm" in payload or "ja4" in payload:
            recs = [payload]
    results = [
        scan_observation(observation_from_record(r), threshold) for r in recs
    ]
    campaigns = correlate(results)
    return to_json(campaigns)


def _records_from_payload(payload: Any) -> tuple[list[dict], int]:
    """Shared payload→(records, threshold) coercion for the new tools."""
    threshold = 35
    recs: list[dict] = []
    if isinstance(payload, str):
        recs = load_records(payload) or []
    elif isinstance(payload, list):
        recs = [r for r in payload if isinstance(r, dict)]
    elif isinstance(payload, dict):
        threshold = _coerce_threshold(payload.get("threshold"))
        if isinstance(payload.get("observations"), list):
            recs = [r for r in payload["observations"] if isinstance(r, dict)]
        elif any(k in payload for k in ("host", "jarm", "ja4", "ja3", "port")):
            recs = [payload]
    return recs, threshold


def export_tool(payload: Any) -> dict[str, Any]:
    """MCP tool: export observations as a STIX 2.1 bundle or MISP event.

    ``format`` in the payload selects ``stix`` (default) or ``misp``. Accepts
    the same observation shapes as ``scan``.
    """
    from .export import to_stix, to_misp

    fmt = "stix"
    if isinstance(payload, dict):
        fmt = str(payload.get("format", "stix")).lower()
    recs, threshold = _records_from_payload(payload)
    results = [scan_observation(observation_from_record(r), threshold) for r in recs]
    return to_misp(results) if fmt == "misp" else to_stix(results)


def beacon_tool(payload: Any) -> dict[str, Any]:
    """MCP tool: beacon-cadence analysis from connection timestamps.

    Accepts ``{"timestamps": [..]}`` (epoch seconds), ``{"text": "log blob"}``,
    or a raw log string. Returns the beacon statistics + verdict.
    """
    from .beacon import analyze_timestamps, analyze_text

    dest = ""
    if isinstance(payload, str):
        return analyze_text(payload).as_dict()
    if isinstance(payload, list):
        return analyze_timestamps(payload).as_dict()
    if isinstance(payload, dict):
        dest = str(payload.get("dest", ""))
        if isinstance(payload.get("timestamps"), list):
            return analyze_timestamps(payload["timestamps"], dest=dest).as_dict()
        if isinstance(payload.get("text"), str):
            return analyze_text(payload["text"], dest=dest).as_dict()
    return analyze_timestamps([], dest=dest).as_dict()


def rules_tool(payload: Any) -> dict[str, Any]:
    """MCP tool: generate deployable detection rules from the signature DB.

    ``format`` selects sigma | suricata | kql | splunk | eql | yara.
    """
    from .rules import generate

    fmt = "sigma"
    if isinstance(payload, dict):
        fmt = str(payload.get("format", "sigma")).lower()
    try:
        text = generate(fmt)
    except ValueError as exc:
        return {"error": str(exc)}
    return {"format": fmt, "rules": text}


# ---------------------------------------------------------------------------
# Stdlib JSON-RPC 2.0 / MCP stdio loop (fallback, no third-party deps).
# ---------------------------------------------------------------------------
_PROTOCOL_VERSION = "2024-11-05"


def _respond(rid: Any, result: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}) + "\n")
    sys.stdout.flush()


def _error(rid: Any, code: int, message: str) -> None:
    sys.stdout.write(json.dumps(
        {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}) + "\n")
    sys.stdout.flush()


def _handle(msg: dict[str, Any]) -> None:
    method = msg.get("method")
    rid = msg.get("id")
    params = msg.get("params") or {}

    if method == "initialize":
        _respond(rid, {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": TOOL_NAME, "version": TOOL_VERSION},
        })
    elif method in ("notifications/initialized", "initialized"):
        pass  # notification, no response
    elif method == "tools/list":
        _respond(rid, {
            "tools": [
                {
                    "name": "scan",
                    "description": _DESCRIPTION,
                    "inputSchema": _INPUT_SCHEMA,
                },
                {
                    "name": "list_signatures",
                    "description": "List the bundled C2 signature database.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "correlate",
                    "description": (
                        "Cluster many observations into shared-infrastructure "
                        "C2 campaigns (same JARM/JA4S/cert across hosts = one "
                        "operator's estate). Defensive triage only."),
                    "inputSchema": _INPUT_SCHEMA,
                },
                {
                    "name": "export",
                    "description": (
                        "Export observations as a STIX 2.1 bundle or MISP event "
                        "(format: stix|misp) — shareable threat intel with "
                        "ATT&CK kill-chain phases. Defensive triage only."),
                    "inputSchema": _INPUT_SCHEMA,
                },
                {
                    "name": "beacon",
                    "description": (
                        "Beacon-cadence analysis from raw connection timestamps "
                        "(mean interval, jitter as coefficient-of-variation, "
                        "regularity score, verdict). Accepts a 'timestamps' "
                        "array or a 'text' log blob."),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "timestamps": {"type": "array",
                                           "items": {"type": "number"}},
                            "text": {"type": "string"},
                            "dest": {"type": "string"},
                        },
                        "additionalProperties": True,
                    },
                },
                {
                    "name": "generate_rules",
                    "description": (
                        "Generate deployable detection rules from the signature "
                        "DB (format: sigma|suricata|kql|splunk|eql|yara)."),
                    "inputSchema": {
                        "type": "object",
                        "properties": {"format": {"type": "string"}},
                        "additionalProperties": True,
                    },
                },
            ]
        })
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            if name == "scan":
                out = scan(args)
            elif name == "list_signatures":
                out = {"families": list_signatures()}
            elif name == "correlate":
                out = correlate_tool(args)
            elif name == "export":
                out = export_tool(args)
            elif name == "beacon":
                out = beacon_tool(args)
            elif name == "generate_rules":
                out = rules_tool(args)
            else:
                _error(rid, -32601, f"unknown tool: {name}")
                return
        except Exception as exc:  # noqa: BLE001 — surface as tool error, never crash loop
            _respond(rid, {
                "content": [{"type": "text", "text": f"error: {exc}"}],
                "isError": True,
            })
            return
        _respond(rid, {
            "content": [{"type": "text", "text": json.dumps(out, indent=2)}],
            "isError": False,
        })
    elif rid is not None:
        _error(rid, -32601, f"method not found: {method}")


def _serve_stdio() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if isinstance(msg, dict):
            _handle(msg)


def _build_fallback_server():
    return _serve_stdio


try:  # pragma: no cover - exercised only when cognis_core is installed
    from cognis_core.mcp import build_mcp_server  # type: ignore

    run_mcp_server = build_mcp_server(
        tool_name=TOOL_NAME,
        description=_DESCRIPTION,
        scan_fn=scan,
    )
except Exception:  # ModuleNotFoundError or any wiring failure -> stdlib server
    run_mcp_server = _build_fallback_server()


if __name__ == "__main__":
    run_mcp_server()
