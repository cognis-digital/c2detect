# integrations/

Adapter stubs so this tool plugs into enterprise systems. Each adapter is small,
dependency-free where possible, and safe to extend via PR.

- `webhook.py` — POST findings to any HTTP endpoint (SIEM/Slack/Jira bridge).

Planned adapters (contributions welcome): `siem_splunk.py`, `siem_sentinel.py`,
`ticketing_jira.py`, `chatops_slack.py`, `sso_oidc.py`, `cloud_aws.py`.
See ../docs/INTEGRATIONS.md for the full matrix.
