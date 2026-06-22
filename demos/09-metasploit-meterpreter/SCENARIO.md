# Metasploit reverse_https Meterpreter

**Expected top attribution:** Metasploit / Meterpreter

A honeypot captured a reverse_https Meterpreter stager: tcp/4444, Metasploit's default multi/handler JARM + JA3, and the tell-tale `/INITM` URI. Classic commodity tooling — still worth catching on default config.

## Run it

```bash
c2detect scan demos/09-metasploit-meterpreter/observations.json
c2detect scan demos/09-metasploit-meterpreter/observations.json --format sarif   # SIEM/code-scanning
```

All indicators here are public, documented out-of-the-box defaults — the values operators are told to change, which is exactly why detecting them works.
