# Havoc 'Demon' agent

**Expected top attribution:** Havoc

A web proxy logged an internal workstation beaconing to tcp/40056 with a `Havoc` server banner and a `/demon` URI — the default profile of the **Havoc** framework's Demon agent. Action: contain, and block the listener JARM at the perimeter.

## Run it

```bash
c2detect scan demos/05-havoc-demon/observations.json
c2detect scan demos/05-havoc-demon/observations.json --format sarif   # SIEM/code-scanning
```

All indicators here are public, documented out-of-the-box defaults — the values operators are told to change, which is exactly why detecting them works.
