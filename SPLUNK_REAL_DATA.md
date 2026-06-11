# Veritas Real Splunk Data Runbook

This moves Veritas from mock evidence to Splunk-backed evidence.

Default local judging does not require Splunk credentials. Run `python server.py` and Veritas uses deterministic `mock-mcp` evidence. Configure Splunk only when you want to demonstrate the optional HEC and REST path.

## Local Docker Quickstart

This is the local setup used for the working Splunk-backed prototype.

```powershell
docker run -d `
  --name veritas-splunk `
  -p 8000:8000 `
  -p 8088:8088 `
  -p 8089:8089 `
  -e "SPLUNK_START_ARGS=--accept-license" `
  -e "SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com" `
  -e "SPLUNK_PASSWORD=VeritasPass123!" `
  -e "SPLUNK_HEC_TOKEN=veritas-hec-token-123" `
  splunk/splunk:latest
```

Splunk Web:

```text
http://localhost:8000
```

Login:

```text
admin / VeritasPass123!
```

Create the Veritas index:

```powershell
docker exec -u splunk veritas-splunk /opt/splunk/bin/splunk add index veritas -auth admin:VeritasPass123!
```

## Data Contract

Veritas expects indexed events with:

- `index=veritas`
- `sourcetype=veritas:incident`
- `incident_id=INC-001`
- `event_id=SEC-3001` through `SEC-3006`

The fields used by the threshold engine are:

- `event_id`
- `incident_id`
- `source_category`
- `summary`
- `user`
- `src_ip`
- `geo`
- `severity`
- `query`
- `tags`

## 1. Configure Splunk HEC

Create or use an HTTP Event Collector token that can write to the `veritas` index.

PowerShell:

```powershell
$env:SPLUNK_HEC_URL="https://localhost:8088/services/collector/event"
$env:SPLUNK_HEC_TOKEN="<hec-token>"
$env:SPLUNK_VERIFY_SSL="false"
$env:VERITAS_SPLUNK_INDEX="veritas"
$env:VERITAS_INCIDENT_ID="INC-001"
```

Preview the payload first:

```powershell
python ingest_to_splunk.py --dry-run
```

Ingest the events:

```powershell
python ingest_to_splunk.py
```

## 2. Configure Splunk REST Search

Veritas pulls indexed evidence through the Splunk REST search API.

PowerShell for local Docker Basic auth:

```powershell
$env:SPLUNK_HOST="https://localhost:8089"
$env:SPLUNK_TOKEN="admin:VeritasPass123!"
$env:SPLUNK_AUTH_SCHEME="Basic"
$env:SPLUNK_VERIFY_SSL="false"
$env:VERITAS_SPLUNK_INDEX="veritas"
$env:VERITAS_INCIDENT_ID="INC-001"
python server.py
```

For a Splunk bearer token, use:

```powershell
$env:SPLUNK_TOKEN="<rest-api-token>"
$env:SPLUNK_AUTH_SCHEME="Bearer"
```

## 3. Verify In Splunk

Run this SPL in Splunk Search:

```spl
index="veritas" sourcetype="veritas:incident"
| spath
| search incident_id="INC-001"
| table _time event_id source_category user src_ip severity summary
```

You should see six events.

## 4. Pull Into Veritas

Open:

```text
http://127.0.0.1:5173
```

Then click:

1. **Pull indexed evidence**
2. **Check thresholds**
3. **Execute approved containment**
4. **Export audit brief**

The provider should show `splunk-rest`, and evidence items should include Splunk job IDs.

## Fallback Behavior

If Splunk is not configured, Veritas stays in `mock-mcp` mode. This keeps the hackathon demo reliable while still supporting real Splunk data when credentials are available.

In both modes, Veritas remains an evidence threshold engine. It does not treat missing logs as proof of safety, does not follow instructions inside log text, and does not run destructive real containment actions.
