"""Scenario 10 - data engineering: ingest Zeek/Suricata JSONL straight in.

**Audience:** detection / data engineers piping NDJSON telemetry.

Real sensors (Zeek, Suricata EVE, EDR exporters) emit one JSON object per line,
not a tidy array. c2detect's loader accepts JSONL/NDJSON transparently and maps
common field names (``dest_ip``, ``server_port``, ``ja3``, ``server_header`` …)
onto its observation model, so a sensor export scans with no reshaping. This
demo builds an NDJSON stream the way a sensor would, parses it with the real
``load_records`` loader, and scans every line.
"""
from _common import rule
from c2detect.core import load_records, observation_from_record, scan_observation


# A handful of lines exactly as a Zeek/EVE-style exporter would emit them:
# heterogeneous field names, one JSON object per line.
NDJSON = "\n".join([
    '{"dest_ip": "198.51.100.23", "server_port": 8888, '
    '"jarm": "3fd21b20d00000021c43d21b21b43d41d6175c3641f5be07f64f5c1e76d31b"}',
    '{"ip_addr": "203.0.113.10", "ja3": "a0e9f5d64349fb13191bc781f81f42e1", '
    '"dst_port": 443}',
    '{"address": "8.8.8.8", "server_header": "gws", "dest_port": 443}',
    '{"server": "10.0.0.5", "http_paths": ["/agent_message"], "port": 7443}',
])


def main() -> None:
    rule("JSONL / NDJSON  -  ingest a sensor stream with no reshaping")

    records = load_records(NDJSON)
    print(f"\nParsed {len(records) if records else 0} NDJSON line(s) "
          "(heterogeneous sensor field names)\n")
    assert records is not None and len(records) == 4

    flagged = 0
    for rec in records:
        obs = observation_from_record(rec)          # field-alias mapping happens here
        res = scan_observation(obs, threshold=35)
        host = obs.host or "(unnamed)"
        if res.top is None:
            print(f"  [CLEAN   ] {host:<16} (port {obs.port})  no C2 indicators")
            continue
        flagged += 1
        print(f"  [{res.top.severity.upper():<8}] {host:<16} {res.top.family} "
              f"({res.top.confidence}%)")

    print(f"\n{flagged} of {len(records)} sensor lines matched a C2 framework. "
          "Field aliases (dest_ip/server_port/server_header/http_paths) were "
          "mapped automatically — the raw EVE/Zeek export scanned as-is.")


if __name__ == "__main__":
    main()
