"""Beacon-cadence analysis from offline connection timestamps.

Defensive / DFIR use only. Standard library only, no network.

The core engine matches a *summarized* beacon interval + jitter against a
family's documented window. This module derives those summary statistics —
and a periodicity verdict — from the **raw connection timestamps** an analyst
already has in a Zeek ``conn.log``, a proxy log, or an EDR network table.

Given a series of connection times (epoch seconds) to one destination, it
computes the inter-arrival deltas and reports:

* mean / median interval,
* jitter as coefficient of variation (stddev / mean) — the scale-free measure
  a defender actually reasons about,
* a **regularity score** (0..1) from an autocorrelation-style self-similarity
  of the delta series, robust to a handful of missed/extra beats,
* a plain-language **verdict**: ``beacon`` (highly regular), ``jittered-beacon``
  (regular interval, deliberate jitter), ``irregular`` (human/organic), or
  ``insufficient-data``.

The result is emitted as a plain dict and can be folded straight into an
:class:`c2detect.core.Observation` (``beacon_interval`` + ``jitter``) so the
signature engine can then attribute it to a family. This is behavioural
detection of call-home cadence — it describes nothing about operating a C2.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

# Below this many intervals we cannot responsibly call something a beacon.
_MIN_INTERVALS = 3

# Regularity at/above which we call a series a (possibly jittered) beacon.
_BEACON_REGULARITY = 0.60
# Coefficient-of-variation at/under which jitter is "low" (near-fixed sleep).
_LOW_CV = 0.15
# CV over which cadence is effectively organic/irregular.
_IRREGULAR_CV = 0.75


@dataclass
class BeaconAnalysis:
    """Verdict + statistics for one destination's connection cadence."""

    dest: str = ""
    samples: int = 0
    intervals: int = 0
    mean_interval: float | None = None
    median_interval: float | None = None
    stdev_interval: float | None = None
    coefficient_of_variation: float | None = None  # stddev/mean == jitter frac
    regularity: float = 0.0                          # 0..1 self-similarity
    verdict: str = "insufficient-data"
    deltas: list[float] = field(default_factory=list)

    @property
    def is_beacon(self) -> bool:
        return self.verdict in ("beacon", "jittered-beacon")

    def as_dict(self) -> dict[str, Any]:
        return {
            "dest": self.dest,
            "samples": self.samples,
            "intervals": self.intervals,
            "mean_interval": self.mean_interval,
            "median_interval": self.median_interval,
            "stdev_interval": self.stdev_interval,
            "coefficient_of_variation": self.coefficient_of_variation,
            "jitter": self.coefficient_of_variation,  # alias for Observation
            "regularity": round(self.regularity, 4),
            "verdict": self.verdict,
            "is_beacon": self.is_beacon,
        }


def _median(xs: Sequence[float]) -> float:
    s = sorted(xs)
    n = len(s)
    mid = n // 2
    if n % 2:
        return s[mid]
    return (s[mid - 1] + s[mid]) / 2.0


def _regularity(deltas: Sequence[float]) -> float:
    """Self-similarity of the delta series in 0..1.

    A perfectly periodic series has identical deltas → score 1.0. We use a
    normalized mean-absolute-deviation around the median (robust to a few
    outliers from missed/extra beats), mapped to [0,1]. Median (not mean) so a
    single huge gap — an analyst pausing capture — doesn't tank an otherwise
    clockwork beacon.
    """
    if len(deltas) < 2:
        return 0.0
    med = _median(deltas)
    if med <= 0:
        return 0.0
    mad = sum(abs(d - med) for d in deltas) / len(deltas)
    # Relative dispersion; 0 → perfectly regular (1.0), >=1 → chaos (0.0).
    rel = mad / med
    return max(0.0, 1.0 - min(1.0, rel))


def analyze_timestamps(
    timestamps: Iterable[float],
    dest: str = "",
) -> BeaconAnalysis:
    """Analyze a series of connection epoch-seconds for beacon cadence."""
    ts = sorted(float(t) for t in timestamps)
    res = BeaconAnalysis(dest=dest, samples=len(ts))
    if len(ts) < _MIN_INTERVALS + 1:
        return res
    deltas = [b - a for a, b in zip(ts, ts[1:]) if b - a >= 0]
    # Drop exact-duplicate timestamps (0 deltas) — not real inter-arrivals.
    deltas = [d for d in deltas if d > 0]
    res.deltas = deltas
    res.intervals = len(deltas)
    if len(deltas) < _MIN_INTERVALS:
        return res

    mean = sum(deltas) / len(deltas)
    var = sum((d - mean) ** 2 for d in deltas) / len(deltas)
    stdev = math.sqrt(var)
    cv = (stdev / mean) if mean > 0 else 0.0

    res.mean_interval = round(mean, 3)
    res.median_interval = round(_median(deltas), 3)
    res.stdev_interval = round(stdev, 3)
    res.coefficient_of_variation = round(cv, 4)
    res.regularity = _regularity(deltas)

    # Verdict.
    if res.regularity >= _BEACON_REGULARITY and cv <= _LOW_CV:
        res.verdict = "beacon"
    elif res.regularity >= _BEACON_REGULARITY and cv < _IRREGULAR_CV:
        res.verdict = "jittered-beacon"
    else:
        res.verdict = "irregular"
    return res


# --------------------------------------------------------------------------- #
# Timestamp parsing from common log / free-text shapes.
# --------------------------------------------------------------------------- #
_EPOCH_RE = re.compile(r"\b(\d{9,10}(?:\.\d+)?)\b")  # 9-10 digit epoch (+frac)
# A fractional epoch (Zeek conn.log `ts` is always `\d+\.\d+`) is far less
# likely to collide with a byte-count / session-id / uid than a bare integer,
# so when a multi-field line has both we prefer it.
_FRAC_EPOCH_RE = re.compile(r"\b(\d{9,10}\.\d+)\b")
_ISO_RE = re.compile(
    r"\b(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\b")


def _iso_to_epoch(y, mo, d, h, mi, s) -> float:
    """Convert a parsed ISO 8601 tuple to epoch seconds (UTC, no tz math).

    We avoid timezone gymnastics: only the *deltas* matter for cadence, so a
    consistent UTC-naive interpretation is sufficient and dependency-free.
    """
    import calendar

    return float(calendar.timegm(
        (int(y), int(mo), int(d), int(h), int(mi), int(s), 0, 0, 0)))


def parse_timestamps(text: str) -> list[float]:
    """Best-effort extract connection timestamps (epoch seconds) from text.

    Recognizes fractional/bare epoch seconds (Zeek conn.log ``ts`` field) and
    ISO-8601 datetimes (proxy / EDR logs). One timestamp per line. Returns them
    in file order; the analyzer sorts. Ignores anything that doesn't look like a
    timestamp.

    On a multi-field line, an ISO datetime wins; otherwise a *fractional* epoch
    (``\\d+.\\d+`` — the Zeek ts shape) is preferred over a bare integer, so a
    leading byte-count / session-id / uid is far less likely to be mistaken for
    the connection time. For single-column timestamp lists this is a no-op.
    """
    out: list[float] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        iso = _ISO_RE.search(line)
        if iso:
            out.append(_iso_to_epoch(*iso.groups()))
            continue
        frac = _FRAC_EPOCH_RE.search(line)
        if frac:
            out.append(float(frac.group(1)))
            continue
        ep = _EPOCH_RE.search(line)
        if ep:
            out.append(float(ep.group(1)))
    return out


def analyze_text(text: str, dest: str = "") -> BeaconAnalysis:
    """Parse timestamps out of a log blob and analyze their cadence."""
    return analyze_timestamps(parse_timestamps(text), dest=dest)
