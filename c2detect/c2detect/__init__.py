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
    Match,
    MatchedIndicator,
    Observation,
    ScanResult,
    Signature,
    TOOL_NAME,
    TOOL_VERSION,
    list_signatures,
    observation_from_text,
    scan_observation,
    scan_text,
)

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "DEFAULT_THRESHOLD",
    "Signature",
    "Observation",
    "Match",
    "MatchedIndicator",
    "ScanResult",
    "scan_observation",
    "scan_text",
    "observation_from_text",
    "list_signatures",
]
