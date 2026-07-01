"""Scenario 11 - quick triage: paste a raw log line, get a verdict.

**Audience:** on-call analysts with a blob of text and no time to format it.

Sometimes all you have is a line out of a proxy log or a chat paste. c2detect's
free-text harvester pulls fingerprints, ports, URIs, banners and beacon cadence
out of an unstructured blob (explicit ``key: value`` pairs *and* free-floating
JARM/JA3/URI tokens) and scans them — no JSON required. This demo runs a couple
of realistic raw blobs through ``scan_text`` and shows what it recovered.
"""
from _common import rule
from c2detect.core import observation_from_text, scan_text


BLOBS = [
    # A proxy/IDS log line with explicit key:value telemetry.
    ("egress-log",
     "host: 198.51.100.7  jarm: "
     "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1  "
     "port: 50050  uri: /submit.php  banner: BeaconData"),
    # A messier blob: free-floating fingerprint + a staging URI, no keys.
    ("chat-paste",
     "saw weird tls to 203.0.113.9 fingerprint "
     "3fd21b20d00000021c43d21b21b43d41d6175c3641f5be07f64f5c1e76d31b "
     "hitting /oscp every minute"),
]


def main() -> None:
    rule("FREE-TEXT TRIAGE  -  scan an unstructured blob, no JSON needed")

    print()
    for label, blob in BLOBS:
        obs = observation_from_text(blob)
        recovered = []
        if obs.jarm:
            recovered.append(f"jarm={obs.jarm[:16]}…")
        if obs.port:
            recovered.append(f"port={obs.port}")
        if obs.uris:
            recovered.append(f"uris={obs.uris[:2]}")
        res = scan_text(blob, threshold=35)
        print(f"  [{label}] recovered: {', '.join(recovered) or '(little)'}")
        if res.top is None:
            print("            verdict : no C2 match\n")
            continue
        print(f"            verdict : {res.top.family} "
              f"[{res.top.severity}] {res.top.confidence}% "
              f"(via {', '.join(sorted({i.klass for i in res.top.indicators}))})\n")

    print("Paste a proxy line, a chat blob, a grep hit — the harvester finds the "
          "fingerprints and URIs and scans them. No reformatting.")


if __name__ == "__main__":
    main()
