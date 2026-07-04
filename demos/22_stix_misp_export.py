"""Scenario 22 - threat intel: export detections as STIX 2.1 and MISP.

**Audience:** CTI teams and ISAC members who share indicators, not screenshots.

A detection is only as useful as your ability to share it. This demo scans a
multi-host incident fixture, then renders the findings two ways: a STIX 2.1
bundle (indicator + malware SDOs with ATT&CK kill-chain phases and
``indicates`` relationships) and a MISP event (one attribute per indicator,
family + ATT&CK tags). Both are deterministic and push straight into a TIP or
SOAR playbook. Fully offline.
"""
from _common import load_observations, rule
from c2detect.core import scan_observations
from c2detect.export import to_stix, to_misp, signatures_to_stix


def main() -> None:
    rule("STIX 2.1 / MISP EXPORT  -  turn detections into shareable intel")

    records = load_observations("11-multi-framework-incident/observations.json")
    results = scan_observations(records, threshold=35)

    bundle = to_stix(results)
    kinds = {}
    for o in bundle["objects"]:
        kinds[o["type"]] = kinds.get(o["type"], 0) + 1
    print("\nSTIX 2.1 bundle:")
    print(f"   objects       : {len(bundle['objects'])}")
    for k in sorted(kinds):
        print(f"     {k:<12}: {kinds[k]}")
    inds = [o for o in bundle["objects"] if o["type"] == "indicator"]
    if inds:
        print(f"   sample pattern: {inds[0]['pattern'][:70]}...")
        print(f"   kill-chain    : {inds[0]['kill_chain_phases'][0]['phase_name']}")

    event = to_misp(results, event_info="C2DETECT incident — multi-framework")
    print("\nMISP event:")
    print(f"   attributes    : {len(event['Event']['Attribute'])}")
    print(f"   tags          : "
          f"{', '.join(t['name'] for t in event['Event']['Tag'][:3])} ...")

    db_feed = signatures_to_stix()
    print("\nBonus - the whole signature DB as a shareable STIX feed "
          f"(no telemetry needed): {len(db_feed['objects'])} objects.")

    assert kinds.get("indicator", 0) >= 1
    assert kinds.get("malware", 0) >= 1
    assert kinds.get("relationship", 0) >= 1

    print("\nShip it:")
    print("   c2detect export incident.json --format stix -o bundle.json")
    print("   c2detect export incident.json --format misp -o event.json")
    print("   c2detect export --db --format stix   # DB as a standalone feed")


if __name__ == "__main__":
    main()
