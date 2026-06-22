# Brute Ratel C4

**Expected top attribution:** Brute Ratel C4

An EDR flagged an unsigned binary; network telemetry shows it reaching a host on tcp/8443 whose JARM + JA3 match **Brute Ratel C4** defaults, with `/admin/menu` requests. BRc4 is a commercial red-team tool abused by intrusion sets — treat as hands-on-keyboard.

## Run it

```bash
c2detect scan demos/07-brute-ratel/observations.json
c2detect scan demos/07-brute-ratel/observations.json --format sarif   # SIEM/code-scanning
```

All indicators here are public, documented out-of-the-box defaults — the values operators are told to change, which is exactly why detecting them works.
