# Deep demo — C2 framework fingerprinting

This scenario shows C2DETECT folding multiple weak/strong indicators into a
confidence-scored attribution, in the spirit of the FoxIO JA4+/JARM DBs.

## Input

`beacon_telemetry.txt` is a (synthetic) authorized blue-team egress capture.
It contains, for two hosts, the kinds of indicators a TLS/HTTP sensor records:

- a **JARM** server fingerprint,
- a listening **port**,
- requested **URI** paths,
- an **HTTP banner**,
- the **x509 certificate** subject/issuer/serial text.

The first host carries the infamous Cobalt Strike defaults (JARM, the
`/submit.php` + `/__utm.gif` beacon URIs, the "Major Cobalt Strike" cert with
serial `146473198`). The second carries Metasploit/Meterpreter defaults
(reverse_https JARM, `/INITM` URI, `MetasploitSelfSignedCA` issuer).

## Run it

```sh
# Scan free-text telemetry (exit code 1 == C2 match found)
python -m c2detect scan demos/02-deep/beacon_telemetry.txt

# JSON for piping into a SIEM
python -m c2detect scan demos/02-deep/beacon_telemetry.txt --format json

# Match explicit indicators (no file needed)
python -m c2detect match \
    --jarm 07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1 \
    --port 443 --uri /submit.php --cert "CN=Major Cobalt Strike serial 146473198"

# Inspect the bundled signature DB
python -m c2detect db
```

## What to expect

The scan attributes the host to **Cobalt Strike** at high confidence (JARM +
cert quirk + two URIs + banner all hit, triggering the multi-strong-indicator
corroboration bonus) and reports a non-zero exit so it can gate a pipeline.
Lower the bar with `--threshold` to surface weaker, single-indicator leads.
