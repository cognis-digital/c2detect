"""Self-check — scan the bundled demo scenarios and report detection coverage.

A confidence/regression surface: it answers "which documented C2 frameworks
does the bundled signature DB actually catch, and does it stay quiet on benign
baselines?" — without any network or active capability. Drives the public
coverage badge ("detects N frameworks across M scenarios") and doubles as a
fast end-to-end smoke test in CI.

Defensive / authorized-triage only.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from .core import (
    DEFAULT_THRESHOLD,
    load_records,
    observation_from_record,
    observation_from_text,
    scan_observation,
    signatures,
)

# Files inside a demo directory we are willing to read. SCENARIO.md (prose) is
# deliberately excluded — it is documentation, not telemetry.
_DEMO_EXT = {".json", ".txt", ".log", ".jsonl", ".ndjson"}


def _demos_dir() -> str:
    """Locate the repo's ``demos/`` directory (sibling of the package dir)."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(here), "demos")


def _families_in_blob(blob: str, threshold: int) -> set[str]:
    fams: set[str] = set()
    records = load_records(blob)
    if records is not None:
        for rec in records:
            res = scan_observation(observation_from_record(rec), threshold=threshold)
            fams.update(m.family for m in res.matches)
    else:
        res = scan_observation(observation_from_text(blob), threshold=threshold)
        fams.update(m.family for m in res.matches)
    return fams


def _is_benign(name: str) -> bool:
    n = name.lower()
    return "benign" in n or "baseline" in n


def _is_feature(name: str) -> bool:
    """Scenarios that demonstrate a *non-signature* feature (live threat-intel
    feeds, campaign correlation) — their detection comes from `--feeds` /
    `correlate`, not the passive signature DB, so the signature self-check
    reports them as informational rather than pass/fail."""
    n = name.lower()
    return ("feed" in n or "intel" in n
            or "correlat" in n or "campaign" in n)


def run_self_check(
    threshold: int = DEFAULT_THRESHOLD,
    demos_dir: Optional[str] = None,
) -> dict[str, Any]:
    """Scan every bundled demo scenario and return a coverage report dict."""
    demos_dir = demos_dir or _demos_dir()
    known = sorted({s.family for s in signatures()})

    scenarios: list[dict[str, Any]] = []
    exercised: set[str] = set()

    if os.path.isdir(demos_dir):
        for name in sorted(os.listdir(demos_dir)):
            sub = os.path.join(demos_dir, name)
            if not os.path.isdir(sub):
                continue
            fams: set[str] = set()
            for fn in sorted(os.listdir(sub)):
                if os.path.splitext(fn)[1].lower() not in _DEMO_EXT:
                    continue
                with open(os.path.join(sub, fn), "r", encoding="utf-8",
                          errors="replace") as fh:
                    fams |= _families_in_blob(fh.read(), threshold)
            exercised |= fams
            kind = ("benign" if _is_benign(name)
                    else "feature" if _is_feature(name)
                    else "signature")
            scenarios.append({
                "scenario": name,
                "kind": kind,
                "benign": kind == "benign",
                "detected": sorted(fams),
                "hit": bool(fams),
            })

    malicious = [s for s in scenarios if s["kind"] == "signature"]
    benign = [s for s in scenarios if s["kind"] == "benign"]
    feature = [s for s in scenarios if s["kind"] == "feature"]
    malicious_detected = sum(1 for s in malicious if s["hit"])
    benign_clean = sum(1 for s in benign if not s["hit"])

    # Healthy = every malicious scenario fired and every benign baseline stayed
    # quiet (no false positives).
    healthy = (malicious_detected == len(malicious)) and (benign_clean == len(benign))

    return {
        "tool": "c2detect",
        "threshold": threshold,
        "known_families": known,
        "known_family_count": len(known),
        "families_exercised": sorted(exercised),
        "families_exercised_count": len(exercised),
        "scenarios_total": len(scenarios),
        "scenarios_with_detection": sum(1 for s in scenarios if s["hit"]),
        "malicious_scenarios": len(malicious),
        "malicious_detected": malicious_detected,
        "benign_scenarios": len(benign),
        "benign_clean": benign_clean,
        "feature_scenarios": len(feature),
        "healthy": healthy,
        "scenarios": scenarios,
    }


def render_table(report: dict[str, Any]) -> str:
    """Human-readable summary of a :func:`run_self_check` report."""
    lines: list[str] = []
    lines.append("c2detect self-check — bundled scenario coverage")
    lines.append("=" * 48)
    for s in report["scenarios"]:
        if s["kind"] == "benign":
            ok = "CLEAN" if not s["hit"] else "FALSE-POS"
            det = "(quiet)" if not s["hit"] else ", ".join(s["detected"])
        elif s["kind"] == "feature":
            ok = "feeds/corr" if not s["hit"] else "DETECT"
            det = ", ".join(s["detected"]) or "(non-signature demo)"
        else:
            ok = "DETECT" if s["hit"] else "MISS"
            det = ", ".join(s["detected"]) or "-"
        lines.append(f"  [{ok:10}] {s['scenario']:34} {det}")
    lines.append("-" * 48)
    lines.append(
        f"  malicious detected : {report['malicious_detected']}/{report['malicious_scenarios']}")
    lines.append(
        f"  benign clean       : {report['benign_clean']}/{report['benign_scenarios']}")
    lines.append(
        f"  frameworks exercised: {report['families_exercised_count']}"
        f"/{report['known_family_count']} in DB")
    lines.append(f"  status             : {'HEALTHY' if report['healthy'] else 'DEGRADED'}")
    return "\n".join(lines)
