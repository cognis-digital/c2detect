"""C2DETECT — C2 infrastructure fingerprint matcher.

Defensive / authorized-triage use only. Reads TLS / network observation
records (JA4/JA4S/JA3/JARM fingerprints, ports, URIs, cert text, HTTP banners)
and scores them against a bundled database of 12+ documented Command-and-
Control framework fingerprints, in the spirit of the FoxIO JA4+/JARM DBs.
No network, no active capability.
"""

from __future__ import annotations

from .core import (
    DEFAULT_THRESHOLD,
    SEVERITY_ORDER,
    Match,
    MatchedIndicator,
    Observation,
    ScanResult,
    Signature,
    TOOL_NAME,
    TOOL_VERSION,
    fails_gate,
    fails_gate_with_ai,
    list_signatures,
    load_records,
    merge_ai_findings,
    observation_from_record,
    observation_from_text,
    scan_observation,
    scan_observations,
    scan_text,
    signatures,
    to_badge,
    to_html,
    to_sarif,
    worst_severity,
)
from .rules import to_sigma, to_suricata, generate
from .correlate import (
    Campaign,
    HostNode,
    SharedPivot,
    correlate,
    correlate_observations,
    PIVOT_WEIGHTS,
    DEFAULT_EDGE_FLOOR,
    DEFAULT_CAMPAIGN_THRESHOLD,
)

__version__ = TOOL_VERSION

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "DEFAULT_THRESHOLD",
    "SEVERITY_ORDER",
    "Signature",
    "Observation",
    "Match",
    "MatchedIndicator",
    "ScanResult",
    "scan_observation",
    "scan_observations",
    "scan_text",
    "observation_from_text",
    "observation_from_record",
    "load_records",
    "list_signatures",
    "to_sarif",
    "to_badge",
    "to_html",
    "worst_severity",
    "fails_gate",
    "fails_gate_with_ai",
    "merge_ai_findings",
    "signatures",
    "to_sigma",
    "to_suricata",
    "generate",
    "Campaign",
    "HostNode",
    "SharedPivot",
    "correlate",
    "correlate_observations",
    "PIVOT_WEIGHTS",
    "DEFAULT_EDGE_FLOOR",
    "DEFAULT_CAMPAIGN_THRESHOLD",
]
