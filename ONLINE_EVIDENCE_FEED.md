# Online Evidence Feed

Veritas can use an online evidence feed before the data is indexed into Splunk. This stage prepares the feed only; it does not change the dashboard and does not disable the current demo fallback yet.

## Source

The feed is built from Splunk's public `attack_data` repository:

- Repository: <https://github.com/splunk/attack_data>
- License: Apache-2.0
- Purpose: curated attack datasets for replaying and validating detections in Splunk

The source manifest is `external_feed_sources.json`. It points to public GitHub raw URLs and the Git LFS object IDs needed to fetch the actual log content.

## Current Sources

| Veritas evidence | Upstream source | Technique | Purpose |
| --- | --- | --- | --- |
| `SEC-3001` | Okta suspicious activity reported by user | `T1078` | Identity/suspicious-login evidence |
| `SEC-3002` | O365 excessive SSO logon errors | `T1078` | MFA/SSO anomaly evidence |
| `SEC-3003` | O365 Azure workload account manipulation | `T1098` | Privilege/account manipulation evidence |
| `SEC-3004` | O365 Azure workload account manipulation | `T1098` | Admin control-plane change evidence |

This intentionally leaves endpoint and object-storage exfiltration evidence absent unless a real source provides it. Veritas should block decisions that require missing evidence.

## Verify the Feed

Generate normalized Veritas events from the online sources:

```powershell
python fetch_external_feed.py --stdout
```

Generate Splunk HEC-ready payloads without sending anything to Splunk:

```powershell
python fetch_external_feed.py --hec-payload --stdout
```

Write normalized events to a local file:

```powershell
python fetch_external_feed.py --output external_veritas_events.json
```

## Next Stage

After approval, the next stage is to ingest this feed into Splunk through HEC, verify the events in `index=veritas`, then change the dashboard so the primary path shows either:

- no live evidence found, or
- real Splunk-indexed evidence returned through MCP.

The dashboard should not show simulated results in the primary judging path after that stage is complete.
