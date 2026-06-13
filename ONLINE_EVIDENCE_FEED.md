# Online Evidence Feed

Veritas can use an online evidence feed before the data is indexed into Splunk. The dashboard now exposes this path as the primary product-facing evidence workflow.

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

## Dashboard Workflow

Run the local server with Splunk REST and HEC environment variables configured, then use the dashboard controls:

1. Open `http://127.0.0.1:5173`.
2. Open **Advanced controls**.
3. Click **Ingest Online Feed**.
4. Veritas fetches the online attack-data sources, normalizes them, writes them through Splunk HEC, waits briefly, and pulls indexed evidence back from Splunk.
5. Click **Analyze Decision** to evaluate thresholds from the indexed evidence.

The dashboard does not show simulated results in this primary judging path. If HEC is configured but Splunk REST/MCP search is not configured, the feed can still be written to Splunk HEC and the UI shows **online feed ingested / indexed search pending**. Veritas does not score decisions until the ingested events are pulled back from the Splunk index.

`server.py` also reads a local `.env` file when present, without overriding variables already set in the shell. This keeps local Splunk REST, MCP, and HEC settings aligned for the dashboard workflow.

## API Endpoint

```text
POST /api/sentinel/ingest-online-feed
```

Request body:

```json
{
  "load_after": true
}
```

When `load_after` is true, the backend ingests through HEC and then calls the normal indexed-evidence search path. Splunk tokens remain server-side.
