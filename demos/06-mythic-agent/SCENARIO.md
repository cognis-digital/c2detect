# Mythic C2 (agent_message)

**Expected top attribution:** Mythic

Threat-intel enrichment on a newly-registered domain resolved to a host on tcp/7443 serving `/agent_message` with a `Mythic` banner and Mythic's default JARM. Pre-position a block and watch for first-stage callbacks.

## Run it

```bash
c2detect scan demos/06-mythic-agent/observations.json
c2detect scan demos/06-mythic-agent/observations.json --format sarif   # SIEM/code-scanning
```

All indicators here are public, documented out-of-the-box defaults — the values operators are told to change, which is exactly why detecting them works.
