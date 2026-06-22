# Multi-framework intrusion (IR)

**Expected top attribution:** Cobalt Strike

An incident-response JARM/flow export from a breached subnet. The intrusion set staged **four** C2s for resilience: Cobalt Strike (primary), Sliver (backup), Havoc, and AdaptixC2. c2detect attributes each host so you can scope and block all of them at once — not just the first one you found.

## Run it

```bash
c2detect scan demos/11-multi-framework-incident/observations.json
c2detect scan demos/11-multi-framework-incident/observations.json --format sarif   # SIEM/code-scanning
```

All indicators here are public, documented out-of-the-box defaults — the values operators are told to change, which is exactly why detecting them works.
