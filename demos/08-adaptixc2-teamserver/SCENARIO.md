# AdaptixC2 teamserver (2025-2026)

**Expected top attribution:** AdaptixC2

Internet-wide scan data (Censys) surfaced a host on tcp/4321 returning `Server: AdaptixC2` / `Adaptix-Version` headers and a `/endpoint/login` path — the default fingerprint of **AdaptixC2**, a fast-growing open-source C2. Branded headers mean it's identifiable on the first unauthenticated probe.

## Run it

```bash
c2detect scan demos/08-adaptixc2-teamserver/observations.json
c2detect scan demos/08-adaptixc2-teamserver/observations.json --format sarif   # SIEM/code-scanning
```

All indicators here are public, documented out-of-the-box defaults — the values operators are told to change, which is exactly why detecting them works.
