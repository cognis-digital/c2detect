# Threat hunt: JARM sweep of egress IPs

**Expected top attribution:** Cobalt Strike

You exported JARM fingerprints for every external IP your org talked to this week (Censys/Shodan style) and fed the lot to c2detect. Most are benign CDNs and SaaS; two are not — a Cobalt Strike team server and a Sliver listener hiding in the noise. This is the everyday hunt c2detect is built for.

## Run it

```bash
c2detect scan demos/12-threat-hunt-jarm-sweep/observations.json
c2detect scan demos/12-threat-hunt-jarm-sweep/observations.json --format sarif   # SIEM/code-scanning
```

All indicators here are public, documented out-of-the-box defaults — the values operators are told to change, which is exactly why detecting them works.
