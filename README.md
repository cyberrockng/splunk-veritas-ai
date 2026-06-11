# Veritas AI

Veritas AI is an **Evidence Threshold Engine for Splunk**. It helps incident response teams decide whether they have enough evidence to safely act, escalate, contain, stand down, or brief leadership.

It is not a generic SOC automation tool, not a false-positive detector, and not a normal SOAR playbook demo. The core product is **response decision assurance**.

Tagline: **Know when you have enough evidence to act.**

## Core Question

Before the team takes a high-impact incident response action, has the required Splunk evidence threshold been met?

## Demo Scenario

The demo uses an admin account takeover incident. Splunk-style events show:

- suspicious impossible-travel login
- MFA anomaly
- privilege escalation
- sensitive API access
- scripted download tooling

Veritas evaluates five proposed response decisions:

- Revoke session token
- Disable admin account
- Block source IP
- Declare no sensitive data accessed
- Close incident as contained

Some decisions are approved or caution-ready. Others are blocked because the evidence threshold has not been met.

## Why This Is Different

False-positive detection asks: "Is this alert real?"

Veritas asks: "Is this response decision justified by evidence?"

That matters because unsafe incident decisions can cause business disruption, legal exposure, missed attackers, or premature containment claims.

## Key Features

- Evidence Threshold Matrix
- Decision Readiness Score
- Evidence Integrity & Blind Spot Panel
- Missing Evidence to SPL Queries
- Blast Radius Warnings
- Judge Demo Flow with live decision spotlight
- One-click Judge Mode
- Evidence-gated containment execution
- Analyst Approval Gate for approve/reject before action
- Evidence Drilldown for each threshold checklist item
- Clickable indicator detail pages for risk, decisions, matrix, blind spots, missing evidence, blast radius, audit brief, and timeline
- Executable custom request runner for analyst-provided incident details
- Functional detail pages that can refresh live evidence, run custom requests, approve/execute actions, and export briefs
- Real Splunk HEC ingestion path
- Live Splunk REST evidence pull
- MCP-shaped Splunk tool-call output
- Decision Audit Brief with Splunk job IDs and search provenance
- Reliable mock mode for local judging without Splunk credentials

## Security Principles

- Missing logs are not proof of safety.
- Logs are untrusted evidence, not instructions.
- Veritas does not invent evidence.
- High-impact actions require evidence threshold plus human approval.
- No real destructive action runs in the demo; containment is simulated safely.
- The demo uses deterministic evidence-bounded logic.

## Run Locally

```powershell
python server.py
```

Then open:

```text
http://127.0.0.1:5173
```

The dashboard indicators open functional pages:

```text
http://127.0.0.1:5173/detail.html?view=risk
http://127.0.0.1:5173/detail.html?view=decisions
http://127.0.0.1:5173/detail.html?view=matrix
http://127.0.0.1:5173/detail.html?view=integrity
http://127.0.0.1:5173/detail.html?view=missing
http://127.0.0.1:5173/detail.html?view=blast
http://127.0.0.1:5173/detail.html?view=audit
http://127.0.0.1:5173/detail.html?view=timeline
```

Optional Splunk REST configuration:

```powershell
$env:SPLUNK_HOST="https://localhost:8089"
$env:SPLUNK_TOKEN="admin:VeritasPass123!"
$env:SPLUNK_AUTH_SCHEME="Basic"
$env:SPLUNK_VERIFY_SSL="false"
$env:VERITAS_SPLUNK_INDEX="veritas"
$env:VERITAS_INCIDENT_ID="INC-001"
python server.py
```

For bearer-token auth, set `SPLUNK_AUTH_SCHEME="Bearer"` and use the token value in `SPLUNK_TOKEN`.
Without Splunk credentials, the app runs in `mock-mcp` mode.

To ingest real demo evidence into Splunk first:

```powershell
$env:SPLUNK_HEC_URL="https://localhost:8088/services/collector/event"
$env:SPLUNK_HEC_TOKEN="<hec-token>"
$env:SPLUNK_VERIFY_SSL="false"
python ingest_to_splunk.py
```

See `SPLUNK_REAL_DATA.md` for the full real-data runbook.

## Demo Flow

Fast path:

1. Click **Run live judge demo**.
2. Veritas pulls indexed Splunk evidence, checks thresholds, executes safe containment, and opens the audit brief.

Manual path:

1. Click **Reset**.
2. Click **Load incident evidence** for mock mode, or **Pull indexed evidence** for Splunk-backed mode.
3. Click **Check thresholds**.
4. Use **Evidence** buttons in the matrix to drill into matched Splunk events, SPL, and job IDs.
5. Approve eligible actions in the **Analyst Approval Gate**.
6. Click **Execute approved containment**.
7. Show that risk drops while unsafe closure/no-data-access claims remain blocked.
8. Show the Evidence Integrity & Blind Spot Panel.
9. Export the Decision Audit Brief.

Executable custom-request path:

1. Open **Investigations** or any indicator detail page.
2. Enter a proposed response task, such as disabling an admin account, blocking an IP, or declaring no sensitive data accessed.
3. Paste incident evidence in plain language.
4. Choose whether the request should execute approved actions or only evaluate readiness.
5. Run the request and review Veritas feedback, readiness changes, blocked decisions, missing SPL evidence, and recommended next action.

This makes the project testable beyond the default demo scenario: judges can feed in their own incident facts and see the system evaluate, approve, block, or hold the response decision.

## Test

With `python server.py` running:

```powershell
python smoke_tests.py
```

## Repository Contents

- `index.html` - Veritas app shell
- `detail.html` - Functional detail page shell for dashboard indicators
- `styles.css` - Responsive dashboard styling
- `app.js` - Frontend workflow controller
- `detail.js` - Detail page controller for live state, custom requests, approvals, actions, and briefs
- `server.py` - Static app server plus Veritas evidence threshold API
- `ingest_to_splunk.py` - Sends Veritas incident evidence into Splunk HEC
- `SPLUNK_REAL_DATA.md` - Real Splunk ingestion and search runbook
- `architecture_diagram.md` - Data flow and component architecture
- `ROADMAP.md` - Follow-up build plan
- `DEMO_SCRIPT.md` - Two-minute judging walkthrough
- `JUDGING_NOTES.md` - Submission positioning and judging notes
- `smoke_tests.py` - Backend smoke tests
- `sample_splunk_events.json` - Legacy sample evidence file from the original MVP
- `LICENSE` - Open source license
