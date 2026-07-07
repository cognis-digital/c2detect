"""Scenario 17 - behavioral hunting: catch the beacon by its cadence.

**Audience:** threat hunters chasing implants that changed every static IOC.

An operator can rotate the cert, the JARM and the URIs — but a beacon that calls
home on a fixed sleep with low jitter still *looks* like a beacon. c2detect
models that behaviour: a family's default sleep window plus a jitter ceiling.
This demo feeds a spread of (interval, jitter) pairs through the real engine and
shows which trip the behavioral heuristic and which are dismissed as too jittery
or off-cadence — no TLS fingerprint required.
"""
from _common import rule
from c2detect.core import Observation, scan_observation


def main() -> None:
    rule("BEACON CADENCE  -  detect the rhythm when every IOC was rotated")

    # (label, mean interval seconds, jitter fraction)
    cases = [
        ("60s sleep, 5% jitter  ", 60, 0.05),
        ("60s sleep, 10% jitter ", 60, 0.10),
        ("60s sleep, 45% jitter ", 60, 0.45),
        ("3600s sleep, 8% jitter", 3600, 0.08),
        ("13s sleep, 2% jitter  ", 13, 0.02),
    ]

    print("\n  A beacon with no TLS fingerprint — only behaviour. Port 443.\n")
    print(f"  {'cadence':<24} verdict")
    print("  " + "-" * 56)
    for label, interval, jitter in cases:
        obs = Observation(host="behavioral", port=443,
                          beacon_interval=interval, jitter=jitter)
        res = scan_observation(obs, threshold=20)
        beaconish = [m for m in res.matches
                     if any(i.klass == "beacon" for i in m.indicators)]
        if beaconish:
            fams = ", ".join(sorted({m.family for m in beaconish}))
            print(f"  {label}   FLAGGED  ({fams})")
        else:
            print(f"  {label}   dismissed (jitter/cadence outside any profile)")

    print("\nLow-jitter, fixed-interval call-home trips the behavioral heuristic "
          "even with zero fingerprint match; a noisy 45%-jitter connection does "
          "not. The rhythm is the tell.")


if __name__ == "__main__":
    main()
