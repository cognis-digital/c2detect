#!/usr/bin/env python3
"""Generate c2detect demo scenarios (observations.json + SCENARIO.md).

Each demo is a realistic, self-contained detection use case grounded in the
real signature-DB indicators, so `c2detect scan <demo>/observations.json`
genuinely fires. Run from the repo root: ``python scripts/gen_demos.py``.
"""
from __future__ import annotations
import json
import os

# (folder, title, intended-top-family, narrative, [observation records])
DEMOS = [
    ("04-sliver-mtls", "Sliver implant over mTLS", "Sliver",
     "A managed-detection analyst pivoted on a suspicious egress flow to an AWS "
     "Lightsail box on tcp/8888. JARM + JA4 match BishopFox **Sliver**'s default "
     "Go-TLS stack, and the 60s/low-jitter call-home seals it. Action: isolate the "
     "host, pull the implant, hunt the JA4 across the fleet.",
     [{"ip": "198.51.100.23", "port": 8888,
       "jarm": "3fd21b20d00000021c43d21b21b43d41d6175c3641f5be07f64f5c1e76d31b",
       "ja4": "t13d190900_9dc949149365_97f8aa674fd9", "uris": ["/oscp"],
       "beacon_interval": 60, "jitter": 0.05}]),

    ("05-havoc-demon", "Havoc 'Demon' agent", "Havoc",
     "A web proxy logged an internal workstation beaconing to tcp/40056 with a "
     "`Havoc` server banner and a `/demon` URI — the default profile of the "
     "**Havoc** framework's Demon agent. Action: contain, and block the listener "
     "JARM at the perimeter.",
     [{"ip": "203.0.113.77", "port": 40056,
       "jarm": "29d29d00029d29d21c29d29d29d29dca5d23a7bab9a9fb1e6b6f6e62b62a4d",
       "http_banner": "Server: Havoc", "uris": ["/demon", "/Havoc/"]}]),

    ("06-mythic-agent", "Mythic C2 (agent_message)", "Mythic",
     "Threat-intel enrichment on a newly-registered domain resolved to a host on "
     "tcp/7443 serving `/agent_message` with a `Mythic` banner and Mythic's default "
     "JARM. Pre-position a block and watch for first-stage callbacks.",
     [{"ip": "192.0.2.55", "port": 7443,
       "jarm": "2ad2ad0002ad2ad22c42d42d000000ad9bf51cc3f5a1e29eecb8d9d5e0b8b8",
       "http_banner": "Mythic", "uris": ["/agent_message", "/new/agent_message"]}]),

    ("07-brute-ratel", "Brute Ratel C4", "Brute Ratel C4",
     "An EDR flagged an unsigned binary; network telemetry shows it reaching a "
     "host on tcp/8443 whose JARM + JA3 match **Brute Ratel C4** defaults, with "
     "`/admin/menu` requests. BRc4 is a commercial red-team tool abused by "
     "intrusion sets — treat as hands-on-keyboard.",
     [{"ip": "198.51.100.200", "port": 8443,
       "jarm": "2ad2ad16d2ad2ad22c2ad2ad2ad2ad6bb8e6b6f6e62b62a4d0f5dd8c0a7c9c",
       "ja3": "72a589da586844d7f0818ce684948eea", "uris": ["/admin/menu", "/api/v1/get"]}]),

    ("08-adaptixc2-teamserver", "AdaptixC2 teamserver (2025-2026)", "AdaptixC2",
     "Internet-wide scan data (Censys) surfaced a host on tcp/4321 returning "
     "`Server: AdaptixC2` / `Adaptix-Version` headers and a `/endpoint/login` path "
     "— the default fingerprint of **AdaptixC2**, a fast-growing open-source C2. "
     "Branded headers mean it's identifiable on the first unauthenticated probe.",
     [{"ip": "203.0.113.150", "port": 4321,
       "http_banner": "Server: AdaptixC2\nAdaptix-Version: v1.2\nYou need to enter the correct connection details.",
       "uris": ["/endpoint/login", "/endpoint", "/endpoint/connect"],
       "cert": "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd"}]),

    ("09-metasploit-meterpreter", "Metasploit reverse_https Meterpreter", "Metasploit / Meterpreter",
     "A honeypot captured a reverse_https Meterpreter stager: tcp/4444, Metasploit's "
     "default multi/handler JARM + JA3, and the tell-tale `/INITM` URI. Classic "
     "commodity tooling — still worth catching on default config.",
     [{"ip": "192.0.2.99", "port": 4444,
       "jarm": "07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d",
       "ja3": "c12f54a3f91dc7bafd92cb59fe009a35", "uris": ["/INITM", "/CONN_"]}]),

    ("10-empire-windows", "PowerShell Empire", "PowerShell Empire",
     "A Windows host is beaconing over tcp/8080 to a server spoofing a "
     "`Microsoft-IIS/7.5` banner on `/admin/get.php` with Empire's default JA3. "
     "**PowerShell Empire** default listener — hunt for the staging cradle in PS logs.",
     [{"ip": "198.51.100.61", "port": 8080,
       "ja3": "4d7a28d6f2263ed61de88ca66eb011e3",
       "http_banner": "Microsoft-IIS/7.5", "uris": ["/admin/get.php", "/news.php"]}]),

    ("11-multi-framework-incident", "Multi-framework intrusion (IR)", "Cobalt Strike",
     "An incident-response JARM/flow export from a breached subnet. The intrusion "
     "set staged **four** C2s for resilience: Cobalt Strike (primary), Sliver "
     "(backup), Havoc, and AdaptixC2. c2detect attributes each host so you can "
     "scope and block all of them at once — not just the first one you found.",
     [{"ip": "10.20.0.10", "port": 443,
       "jarm": "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1",
       "ja3": "a0e9f5d64349fb13191bc781f81f42e1", "uris": ["/submit.php"],
       "beacon_interval": 60, "jitter": 0.0},
      {"ip": "10.20.0.11", "port": 8888,
       "jarm": "3fd21b20d00000021c43d21b21b43d41d6175c3641f5be07f64f5c1e76d31b",
       "ja4": "t13d190900_9dc949149365_97f8aa674fd9"},
      {"ip": "10.20.0.12", "port": 40056,
       "jarm": "29d29d00029d29d21c29d29d29d29dca5d23a7bab9a9fb1e6b6f6e62b62a4d",
       "http_banner": "Havoc", "uris": ["/demon", "/Havoc/"]},
      {"ip": "10.20.0.13", "port": 4321,
       "http_banner": "Server: AdaptixC2\nAdaptix-Version: v1.2",
       "uris": ["/endpoint/login", "/endpoint"],
       "cert": "O=Internet Widgits Pty Ltd"}]),

    ("12-threat-hunt-jarm-sweep", "Threat hunt: JARM sweep of egress IPs", "Cobalt Strike",
     "You exported JARM fingerprints for every external IP your org talked to this "
     "week (Censys/Shodan style) and fed the lot to c2detect. Most are benign CDNs "
     "and SaaS; two are not — a Cobalt Strike team server and a Sliver listener "
     "hiding in the noise. This is the everyday hunt c2detect is built for.",
     [{"ip": "151.101.1.10", "port": 443, "jarm": "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1948923f5f3"},
      {"ip": "142.250.80.46", "port": 443, "jarm": "29d29d00029d29d00041d41d0000007a9c1f6b2e5e9f0e0d3a7c9b8e6b6f6e"},
      {"ip": "13.107.42.14", "port": 443, "jarm": "21d19d00021d21d21c21d19d21d21d1aa3a7bab9a9fb1e6b6f6e62b62a4d0f"},
      {"ip": "45.77.65.211", "port": 443,
       "jarm": "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"},
      {"ip": "207.148.0.9", "port": 8888,
       "jarm": "3fd21b20d00000021c43d21b21b43d41d6175c3641f5be07f64f5c1e76d31b",
       "ja4": "t13d190900_9dc949149365_97f8aa674fd9"}]),
]


def main() -> int:
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demos")
    for folder, title, family, narrative, obs in DEMOS:
        d = os.path.join(root, folder)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "observations.json"), "w", encoding="utf-8") as fh:
            json.dump(obs, fh, indent=2)
        scenario = (
            f"# {title}\n\n"
            f"**Expected top attribution:** {family}\n\n"
            f"{narrative}\n\n"
            "## Run it\n\n"
            "```bash\n"
            f"c2detect scan demos/{folder}/observations.json\n"
            f"c2detect scan demos/{folder}/observations.json --format sarif   # SIEM/code-scanning\n"
            "```\n\n"
            "All indicators here are public, documented out-of-the-box defaults — the "
            "values operators are told to change, which is exactly why detecting them works.\n"
        )
        with open(os.path.join(d, "SCENARIO.md"), "w", encoding="utf-8") as fh:
            fh.write(scenario)
        print(f"wrote demos/{folder}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
