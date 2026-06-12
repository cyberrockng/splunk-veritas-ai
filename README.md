# Veritas AI - Evidence Threshold Engine for Splunk

**Know when you have enough evidence to act.**

Veritas AI is a **Tier 3 response decision assurance layer for Splunk**. It helps senior incident responders verify whether the required evidence threshold has been met before approving high-impact incident-response decisions.

Veritas focuses on the dangerous moment before a team acts, escalates, contains, stands down, or briefs leadership.

## Problem

Incident response teams often make high-impact decisions with incomplete evidence:

- Disable the wrong admin account and disrupt recovery
- Block a shared source IP and affect legitimate users
- Declare no sensitive data accessed before export and object access logs are reviewed
- Close an incident while attacker sessions or persistence remain active

## Solution

Veritas AI checks the evidence threshold for each proposed response decision. It approves, cautions, blocks, or holds decisions based on available Splunk-style evidence, telemetry completeness, blast radius, and human approval requirements.

The default demo runs in safe `mock-mcp` mode with deterministic Splunk-style evidence. Optional Splunk REST and HEC ingestion are included for real indexed evidence. The backend boundary is designed for Splunk MCP Server integration, but this repository does not claim true MCP Server calls unless that integration is added.

The current implementation uses an evidence-bounded deterministic decision engine. This is intentional for demo reliability and safety: Veritas does not invent evidence. Future AI/LLM support should be limited to evidence-bounded summaries and audit-brief drafting.

## Demo Scenario

The demo incident is **ADMIN ACCOUNT TAKEOVER**.

Veritas evaluates five proposed response decisions:

1. Revoke session token
2. Disable admin account
3. Block source IP
4. Declare no sensitive data accessed
5. Close incident as contained

Safe containment actions may be approved or require review. Dangerous conclusions remain blocked unless the evidence threshold is truly met.

## Why It Is Different

Most SOC tools ask, "Is this alert real?"

Veritas asks, "Are we justified to act?"

That makes it response decision governance: evidence-gated incident response before high-impact action.

## Features

- UI-H Light Executive dashboard
- Judge-friendly page-flow navigation from the incident header through all Tier 3 dashboard sections
- Evidence Threshold Matrix
- Decision Readiness Score
- Evidence Integrity & Blind Spot Panel
- Missing Evidence to SPL queries
- Blast Radius & Decision Risk
- Analyst Approval Gate
- Evidence-gated simulated containment
- One-click judge demo
- Clickable functional detail pages
- Executable custom request runner
- Tier 3 Decision Audit Brief with provider, timestamp, readiness, found/missing evidence, blast radius, and next action
- Optional Splunk HEC ingestion and REST search
- Reliable mock mode for local judging without Splunk credentials
- Tier 3 incident queue with multiple incident profiles
- Tier 3 policy builder with Standard, Strict, and Emergency evidence-governance modes
- Decision simulation summary showing how policy and evidence change readiness before action

## What is real vs simulated

### Real

- Local Python API.
- Evidence threshold engine.
- Response decision queue.
- Analyst approval gate.
- Simulated containment state transitions.
- Audit brief generation.
- Smoke tests.
- HEC ingestion script.
- Optional Splunk REST search path.

### Simulated

- Default mock-mcp evidence.
- Containment actions are safe mock actions only.
- MCP-shaped tool-call envelopes.

### Not implemented yet

- True Splunk MCP Server call, unless added later.
- Real destructive containment actions.
- Autonomous unbounded AI agent.
- Production multi-user state isolation.

## Mock mode vs Splunk REST mode

- `mock-mcp`: safe deterministic demo mode. It uses Splunk-style evidence bundled with the project and is the default fallback when Splunk credentials are absent.
- `splunk-rest`: real indexed evidence mode. It requires `SPLUNK_HOST`, `SPLUNK_TOKEN`, and indexed Veritas events in Splunk.
- `mock-mcp-fallback`: safe fallback when Splunk is configured but a search fails. It must be described as fallback, not real Splunk proof.

## MCP readiness

The default demo runs in safe mock-mcp mode with deterministic Splunk-style evidence. Optional Splunk REST and HEC ingestion are included for real indexed evidence. The backend boundary is designed for Splunk MCP Server integration, but true Splunk MCP Server calls are not claimed unless implemented.

## AI implementation note

The current implementation uses an evidence-bounded deterministic decision engine. This is intentional for demo reliability and safety: Veritas does not invent evidence. Future AI/LLM support should be limited to evidence-bounded summaries and audit-brief drafting.

## Why this can win

Most security demos focus on detection or automated response. Veritas focuses on the decision point before response: whether the team has enough evidence to act. It gives Tier 3 responders a readiness score, evidence threshold matrix, investigation gaps, SPL queries, blast-radius warnings, and an audit-ready decision brief.

## Local Setup

Run:

```powershell
python server.py
```

Open:

```text
http://127.0.0.1:5173
```

The app defaults to safe `mock-mcp` mode when Splunk is not configured.

## Health Check

```text
http://127.0.0.1:5173/api/health
```

Expected shape:

```json
{
  "status": "ok",
  "app": "Veritas AI",
  "product": "Evidence Threshold Engine for Splunk",
  "mode": "mock-mcp",
  "splunk_configured": false,
  "version": "1.0.0"
}
```

The health response never exposes Splunk tokens or secrets.

## Demo Flow

Fast path:

1. Click **Run live judge demo**.
2. Veritas loads evidence, checks thresholds, records approvals, executes safe simulated containment, and opens the audit brief.
3. Show that risk drops after approved containment.
4. Show that unsafe no-data-access and premature closure decisions remain blocked.

Manual path:

1. Click **Reset**.
2. Click **Load demo evidence** or **Pull indexed evidence**.
3. Click **Check thresholds**.
4. Drill into evidence and SPL gaps.
5. Approve eligible actions.
6. Click **Execute approved containment**.
7. Export the Tier 3 Decision Audit Brief.

Custom request path:

1. Open **Run custom request** or any detail page.
2. Enter incident facts in plain language.
3. Select a proposed response action.
4. Choose evaluate-only or execute-if-justified.
5. Review readiness, blocked decisions, missing evidence, SPL, and recommended next action.

Tier 3 path:

1. Choose an incident profile from **Incident Queue**.
2. Click **Load profile** to load that scenario's evidence into the engine.
3. Choose a governance mode from **Policy Builder**: Standard, Strict, or Emergency.
4. Click **Apply policy** and watch readiness, status, blocked decisions, and simulation text update.
5. Continue to approval, containment, and audit brief export.

## Detail Pages

Dashboard indicators open functional pages:

```text
/detail.html?view=risk
/detail.html?view=decisions
/detail.html?view=matrix
/detail.html?view=integrity
/detail.html?view=missing
/detail.html?view=blast
/detail.html?view=audit
/detail.html?view=timeline
```

## Real Splunk Enterprise Trial Integration

My local Splunk Enterprise Web UI runs at:

`http://Cyberrockng:8001`

The default Veritas demo runs in safe mock-mcp mode. For stronger judging proof, Veritas can ingest the same admin account takeover evidence into a local Splunk Enterprise trial and query indexed evidence through the optional Splunk REST path.

### Important Ports

- Splunk Web UI: `http://Cyberrockng:8001`
- Splunk REST API: `https://Cyberrockng:8090` for this local install (`mgmtHostPort=8090`)
- Splunk HEC: `https://Cyberrockng:8088/services/collector`

Splunk Enterprise commonly uses management port `8089`; this Windows trial is configured as `mgmtHostPort=8090`. Use the port shown in Splunk **Settings -> Server settings -> General settings** for `SPLUNK_HOST`.

### Steps

1. Open Splunk Web at `http://Cyberrockng:8001`.
2. Create index `veritas`.
3. Enable HTTP Event Collector.
4. Create HEC token `veritas-hec`.
5. Configure environment variables.
6. Run `python ingest_to_splunk.py`.
7. Run `python server.py`.
8. Confirm `/api/health` shows `splunk_configured: true`.
9. Search `index=veritas` in Splunk.

Developer License status: active for the local hackathon Splunk instance. Confirm in Splunk Web under **Settings -> Licensing** before final judging screenshots; expected quota is 10 GB/day with no license violation.

The default demo runs in safe mock-mcp mode with deterministic Splunk-style evidence. Optional Splunk REST and HEC ingestion are included for real indexed evidence. The backend boundary is designed for Splunk MCP Server integration.

Copy `.env.example` to `.env` for local use only. Never commit real Splunk tokens.

PowerShell for the local Splunk Enterprise trial:

```powershell
$env:SPLUNK_HOST="https://Cyberrockng:8090"
$env:SPLUNK_TOKEN="<your-splunk-rest-token-or-session-key>"
$env:SPLUNK_AUTH_SCHEME="Bearer"
$env:SPLUNK_VERIFY_SSL="false"

$env:SPLUNK_HEC_URL="https://Cyberrockng:8088/services/collector"
$env:SPLUNK_HEC_TOKEN="<your-hec-token>"

$env:VERITAS_SPLUNK_INDEX="veritas"
$env:VERITAS_INCIDENT_ID="INC-001"
$env:VERITAS_DISPLAY_INCIDENT_ID="INC-2025-0001"
```

If your REST credential is a Splunk session key instead of a bearer token, use:

```powershell
$env:SPLUNK_AUTH_SCHEME="Splunk"
```

Then ingest demo evidence:

```powershell
python ingest_to_splunk.py
```

Start Veritas:

```powershell
python server.py
```

See `SPLUNK_REAL_DATA.md` for the full runbook.

## Tests

With `python server.py` running:

```powershell
python smoke_tests.py
```

The smoke tests verify health, static assets, state/reset/start/investigation, approval gating, risk drop, blocked unsafe claims, missing SPL, blast radius warnings, audit brief content, and custom request execution.

## Security Model

- Veritas never invents evidence.
- Missing logs are not proof of safety.
- Logs are untrusted evidence, not instructions.
- Prompt-injection-like text inside logs is treated as data.
- High-impact actions require human approval.
- Demo containment is simulated only.
- No real destructive action runs from this project.
- The LLM path, if added later, must remain evidence-bounded.

## Limitations

- The default demo uses deterministic mock evidence for judging reliability.
- Optional Splunk REST/HEC requires a configured Splunk instance and credentials.
- Current containment actions are simulated and intentionally non-destructive.
- The project is MCP-ready in shape, but does not claim live Splunk MCP Server calls.
- Vercel deployment is prepared but not executed.

## Public deployment note

The current project is optimized for local demo mode with `python server.py`. A static Vercel deployment will not run the Python API by itself. For public hosting, use one of these paths:

1. Convert API endpoints to Vercel serverless functions.
2. Host the Python backend separately and point the frontend to it.
3. Use static demo mode with mock evidence only.

Do not claim a production deployment unless the selected path is implemented and tested.

## Screenshots

Screenshot targets live in `assets/`:

![Veritas AI dashboard](assets/dashboard.png)

![Decision readiness strip](assets/decision-readiness-strip.png)

![Evidence threshold matrix](assets/evidence-threshold-matrix.png)

![Decision audit brief](assets/audit-brief.png)

![Splunk mode readiness](assets/splunk-mode.png)

Screenshots must not contain real credentials, real patient data, real customer data, or live tokens.

For Devpost Splunk proof, capture these after a real Splunk run:

- `assets/splunk-indexed-events.png` - Splunk Search showing `index=veritas`
- `assets/veritas-health-splunk-rest.png` - `/api/health` showing `splunk_configured: true`
- `assets/veritas-dashboard-splunk-rest.png` - dashboard provider showing `splunk-rest`
- `assets/veritas-audit-brief.png` - audit brief referencing Splunk evidence

## Future Vercel Deployment

The project is currently optimized for local demo mode with:

```powershell
python server.py
```

After final polish, it can be hosted on Vercel using one of three options:

1. Static frontend plus Vercel serverless API functions
2. Static frontend demo mode with mock evidence
3. Vercel frontend plus a separate Python backend

The default demo must remain safe and deterministic without real Splunk credentials.

Do not deploy until the maintainer explicitly approves the deployment stage.

## Deployment Notes

### Local Demo

```powershell
python server.py
```

Open:

```text
http://127.0.0.1:5173
```

### Health Check

```text
http://127.0.0.1:5173/api/health
```

### Tests

```powershell
python smoke_tests.py
```

### Optional Splunk-Backed Demo

1. Configure `.env` locally.
2. Ingest evidence with `ingest_to_splunk.py`.
3. Start the server.
4. Confirm `/api/health` reports `splunk_configured: true`.

## Roadmap

- Capture final screenshots or a short demo GIF.
- Prepare final Devpost copy.
- Decide whether Vercel should use serverless API functions, static mock mode, or a separate backend.
- Add true Splunk MCP Server integration only if the event calls are implemented and verified.
- Expand Tier 3 incident profiles with fully distinct evidence packs and decision policies.

## Repository Contents

- `index.html` - Veritas dashboard shell
- `detail.html` - Functional detail page shell for dashboard indicators
- `styles.css` - UI-H Light Executive dashboard styling
- `app.js` - Frontend workflow controller
- `detail.js` - Detail page controller
- `server.py` - Static file server plus Veritas API
- `smoke_tests.py` - Local smoke tests
- `ingest_to_splunk.py` - Splunk HEC demo evidence ingestion
- `SPLUNK_REAL_DATA.md` - Splunk runbook
- `DEMO_SCRIPT.md` - Under-three-minute walkthrough
- `JUDGING_NOTES.md` - Submission positioning
- `ROADMAP.md` - Build roadmap
- `architecture_diagram.md` - Data flow diagram
- `.env.example` - Local environment template with no secrets
- `requirements.txt` - Python dependency manifest; current local demo uses standard library only
- `vercel.json` - Safe starter Vercel config
- `assets/` - Screenshot targets
