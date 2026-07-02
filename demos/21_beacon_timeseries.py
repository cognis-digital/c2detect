"""Scenario 21 - DFIR: prove beaconing from raw connection timestamps.

**Audience:** DFIR analysts staring at a Zeek conn.log wondering if a host is
beaconing.

The core engine attributes a *summarized* interval+jitter to a C2 family. But
where do those numbers come from? This demo takes the raw connection
timestamps (epoch seconds, exactly what a conn.log ``ts`` column gives you),
derives the mean interval, the jitter as a scale-free coefficient of variation,
and a regularity score, then renders the verdict. It runs fully offline against
a bundled 30-connection fixture.
"""
from _common import rule, scenario
from c2detect.beacon import analyze_text


def main() -> None:
    rule("BEACON TIMESERIES  -  cadence verdict from raw connection timestamps")

    with open(scenario("21-beacon-timeseries/conn_timestamps.log"),
              "r", encoding="utf-8") as fh:
        blob = fh.read()

    a = analyze_text(blob, dest="45.77.65.211:443")

    print(f"\nDestination        : {a.dest}")
    print(f"Connections        : {a.samples}  ({a.intervals} inter-arrivals)")
    print(f"Mean interval      : {a.mean_interval}s   (median {a.median_interval}s)")
    print(f"Jitter (CV)        : {a.coefficient_of_variation}   "
          f"(stddev {a.stdev_interval}s)")
    print(f"Regularity score   : {a.regularity:.3f}  (1.0 = clockwork)")
    print(f"\n>>> VERDICT: {a.verdict.upper()}"
          + ("   [BEACON — hunt this host]" if a.is_beacon else ""))

    assert a.is_beacon, "fixture is a jittered 60s beacon"
    assert a.verdict in ("beacon", "jittered-beacon")

    print("\nFold straight into the signature engine:")
    print("   obs.beacon_interval, obs.jitter = "
          f"{a.mean_interval}, {a.coefficient_of_variation}")
    print("   ...then `c2detect match --beacon-interval ... --jitter ...` "
          "attributes it to a family.")


if __name__ == "__main__":
    main()
