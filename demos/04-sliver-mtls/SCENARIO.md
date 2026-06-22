# Sliver implant over mTLS

**Expected top attribution:** Sliver

A managed-detection analyst pivoted on a suspicious egress flow to an AWS Lightsail box on tcp/8888. JARM + JA4 match BishopFox **Sliver**'s default Go-TLS stack, and the 60s/low-jitter call-home seals it. Action: isolate the host, pull the implant, hunt the JA4 across the fleet.

## Run it

```bash
c2detect scan demos/04-sliver-mtls/observations.json
c2detect scan demos/04-sliver-mtls/observations.json --format sarif   # SIEM/code-scanning
```

All indicators here are public, documented out-of-the-box defaults — the values operators are told to change, which is exactly why detecting them works.
