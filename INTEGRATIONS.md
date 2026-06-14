# Integrations

**c2detect** plugs into your stack through [`cognis-connect`](https://github.com/cognis-digital/cognis-connect),
the suite's integration SDK. It maps any tool's JSON into a canonical **Finding** and
forwards it to the platforms that fit the **MCP / agent security** domain.

```bash
pip install "git+https://github.com/cognis-digital/cognis-connect.git"
```

## Forward findings to a platform

Once `c2detect` emits JSON findings, pipe them straight to a destination — `--dry-run`
previews the exact request without sending:

```bash
c2detect ... --format json | cognis-connect emit --to sigma   # Sigma rules
c2detect ... --format json | cognis-connect emit --to splunk --url $URL --token $TOK   # Splunk HEC
c2detect ... --format json | cognis-connect emit --to webhook --url $URL --token $TOK   # generic webhook
```

Recommended for this domain: **sigma, splunk, webhook**. The full set is
`stix · taxii · misp · sigma · splunk · elastic · slack · discord · webhook · brief`.

## From Python

`normalize()` maps any record (field/indicator aliases handled) into a `Finding`, so this
works whatever `c2detect` outputs:

```python
from cognis_connect import normalize, sigma
findings = [normalize(rec, source="c2detect") for rec in records]   # records = your JSON output
print(sigma.to_event(findings))
```

## Other channels

- **AI enrichment / summaries** — point add-ins at an [`edgemesh`](https://github.com/cognis-digital/edgemesh)
  `/v1` gateway (`OPENAI_BASE_URL`); `cognis-connect emit --to brief` writes an analyst summary.
- **Composition patterns & reference stacks** — see [INTEROP.md](INTEROP.md).

> Integration backbone for the 300+ suite. **[github.com/cognis-digital](https://github.com/cognis-digital)**
