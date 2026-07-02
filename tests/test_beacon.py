"""Tests for beacon-cadence analysis from connection timestamps."""
from __future__ import annotations

import random

import pytest

from c2detect.beacon import (
    analyze_timestamps, analyze_text, parse_timestamps, BeaconAnalysis,
    _median, _regularity,
)


class TestFixedBeacon:
    def test_perfect_60s_is_beacon(self):
        ts = [1000.0 + i * 60 for i in range(12)]
        a = analyze_timestamps(ts, dest="c2.example")
        assert a.verdict == "beacon"
        assert a.is_beacon
        assert a.mean_interval == 60.0
        assert a.coefficient_of_variation == 0.0
        assert a.regularity == pytest.approx(1.0)
        assert a.dest == "c2.example"

    def test_stats_populated(self):
        ts = [0, 30, 60, 90, 120]
        a = analyze_timestamps(ts)
        assert a.median_interval == 30.0
        assert a.stdev_interval == 0.0
        assert a.intervals == 4
        assert a.samples == 5


class TestJitteredBeacon:
    def test_wide_jitter_still_beacon_class(self):
        random.seed(7)
        ts = [1000.0]
        for _ in range(15):
            ts.append(ts[-1] + 60 + random.uniform(-25, 25))
        a = analyze_timestamps(ts)
        assert a.verdict == "jittered-beacon"
        assert a.is_beacon
        assert 0.15 < a.coefficient_of_variation < 0.75

    def test_low_jitter_is_plain_beacon(self):
        random.seed(1)
        ts = [1000.0]
        for _ in range(20):
            ts.append(ts[-1] + 60 + random.uniform(-5, 5))
        a = analyze_timestamps(ts)
        assert a.verdict == "beacon"


class TestIrregular:
    def test_organic_traffic_is_irregular(self):
        ts = [1000, 1005, 1300, 1310, 5000, 5001, 9000, 9200]
        a = analyze_timestamps(ts)
        assert a.verdict == "irregular"
        assert not a.is_beacon

    def test_insufficient_data(self):
        assert analyze_timestamps([1, 2]).verdict == "insufficient-data"
        assert analyze_timestamps([]).verdict == "insufficient-data"

    def test_duplicate_timestamps_dropped(self):
        # All-identical timestamps => no positive deltas => insufficient.
        a = analyze_timestamps([1000] * 10)
        assert a.verdict == "insufficient-data"


class TestParsing:
    def test_epoch_lines(self):
        txt = "\n".join(str(1700000000 + i * 60) for i in range(5))
        ts = parse_timestamps(txt)
        assert len(ts) == 5
        assert ts[1] - ts[0] == 60

    def test_iso_lines(self):
        txt = "2023-11-14T22:16:40\n2023-11-14T22:17:40\n2023-11-14 22:18:40"
        ts = parse_timestamps(txt)
        assert len(ts) == 3
        assert ts[1] - ts[0] == 60

    def test_comments_and_junk_ignored(self):
        txt = "# header\n1700000000\ngarbage line\n1700000060\n"
        assert len(parse_timestamps(txt)) == 2

    def test_multifield_prefers_fractional_epoch(self):
        # Zeek-style: uid + byte-count integers precede the fractional ts.
        lines = []
        for i in range(6):
            ts = 1700000000.5 + i * 60
            lines.append(f"C4f8s0{i} 1234567890 {ts:.6f} 45.77.65.211 443")
        a = analyze_text("\n".join(lines))
        # must lock onto the 60s cadence, not the constant byte-count integer
        assert a.mean_interval == 60.0
        assert a.verdict == "beacon"

    def test_analyze_text_end_to_end(self):
        txt = "\n".join(str(1700000000 + i * 30) for i in range(10))
        a = analyze_text(txt, dest="host")
        assert a.verdict == "beacon"
        assert a.mean_interval == 30.0


class TestAsDict:
    def test_dict_has_jitter_alias(self):
        d = analyze_timestamps([0, 60, 120, 180, 240]).as_dict()
        assert d["jitter"] == d["coefficient_of_variation"]
        assert d["verdict"] == "beacon"
        assert d["is_beacon"] is True

    def test_dataclass_default(self):
        a = BeaconAnalysis()
        assert a.verdict == "insufficient-data"
        assert not a.is_beacon


class TestHelpers:
    def test_median_odd_even(self):
        assert _median([1, 2, 3]) == 2
        assert _median([1, 2, 3, 4]) == 2.5

    def test_regularity_bounds(self):
        assert _regularity([60, 60, 60]) == pytest.approx(1.0)
        assert _regularity([1]) == 0.0
        # wildly varying deltas → low regularity
        assert _regularity([1, 1000, 1, 1000]) < 0.2


def test_public_api():
    import c2detect
    assert callable(c2detect.analyze_timestamps)
    assert callable(c2detect.analyze_beacon_text)
    assert callable(c2detect.parse_timestamps)
    a = c2detect.analyze_timestamps([0, 60, 120, 180, 240])
    assert isinstance(a, c2detect.BeaconAnalysis)
