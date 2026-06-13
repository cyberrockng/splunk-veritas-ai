# Devpost Submission Draft

## Project Title

Veritas AI - Evidence Threshold Engine for Splunk

## Tagline

Know when you have enough evidence to act.

## Track

Security

## Bonus Fit

Best Splunk Integration / MCP-enabled workflow

## Short Description

Veritas AI is a Tier 3 incident response decision assurance layer for Splunk. It helps responders decide whether the available evidence is strong enough before taking high-impact actions like revoking sessions, disabling admin accounts, blocking source IPs, briefing leadership, or closing an incident.

Most SOC tools ask, "Is this alert real?" Veritas asks, "Are we justified to act?"

## Inspiration

Incident responders often have to act quickly, but the riskiest mistakes happen when teams act before the evidence threshold is met. A team may disable the wrong account, block a shared IP, declare that no data was accessed too early, or close an incident while attacker activity remains unresolved. Veritas turns that uncertainty into a governed, auditable decision workflow.

## What It Does

Veritas evaluates response decisions against required evidence thresholds. It shows:

- Residual risk score.
- Decision readiness for each proposed response.
- Evidence threshold matrix.
- Missing evidence mapped to SPL.
- Blast-radius warnings.
- Evidence integrity and blind spots.
- Analyst approval gate.
- Case timeline and normalized evidence findings.
- Tier 3 decision audit brief.

Users can feed in their own incident evidence through the dashboard, upload supported evidence files, or use the online Splunk evidence flow when Splunk HEC/search is configured.

## How We Built It

The project uses a local Python backend and browser frontend. The backend contains the evidence threshold engine, response decision scoring, audit brief generation, Splunk REST/HEC integration, and dashboard-to-MCP routing. The frontend provides the incident dashboard, evidence intake workflow, detail pages, approval gate, and audit output.

Splunk integration paths include:

- Splunk HEC ingestion.
- Splunk REST search.
- A stdio MCP server exposing Splunk tools.
- Dashboard-to-local-API-to-MCP-to-Splunk routing.
- Online evidence ingestion from allowlisted Splunk attack-data sources.

The app defaults to deterministic mock mode when Splunk credentials are absent so judges can run the project reliably without exposing secrets.

## AI / Agentic Workflow

Veritas is evidence-bounded and agent-ready. In this build, the decision engine is deterministic and does not autonomously invent evidence or perform destructive actions. The agentic workflow is expressed through MCP-enabled Splunk search/ingestion tools, evidence-governed decision routing, and human approval gates. Future LLM features should remain evidence-bounded and limited to summaries, audit drafting, and analyst assistance.

## Splunk Usage

Veritas uses Splunk as the evidence system of record. It can ingest normalized events through HEC, search indexed evidence through Splunk REST, and route dashboard evidence loading through a real stdio MCP server. The audit brief records provider, search provenance, found evidence, missing SPL, readiness, blast radius, approval state, and safety notes.

## Security Model

Veritas treats evidence as hostile input:

- Logs are data, not instructions.
- Missing logs are not proof of safety.
- Splunk tokens stay server-side.
- Online feed sources are allowlisted and normalized before Splunk ingestion.
- Static file serving is allowlisted.
- Deployment security tests verify path traversal protection, CORS allowlisting, security headers, and optional staging authentication.
- Containment actions are simulated for safety.

## Challenges

The hardest part was making the product feel realistic without overstating the implementation. We had to separate real evidence scoring, Splunk ingestion, MCP routing, and audit generation from safe simulated containment. Another challenge was making the dashboard meaningful only when evidence is supplied, so Veritas behaves like a workable product instead of a prefilled demo.

## Accomplishments

- Built an evidence intake workflow for customer-supplied incident data.
- Added case history and previous-run persistence.
- Added Splunk HEC, REST, and MCP integration paths.
- Added a real MCP server for Splunk tools.
- Added deployment security tests and optional staging authentication.
- Created a decision audit workflow that blocks unsafe claims until evidence thresholds are met.

## What We Learned

Security automation should not only ask whether an alert is real. It should also ask whether a response decision is justified, reversible, and supported by enough evidence. We also learned that being explicit about what is real, simulated, and future work makes a hackathon project more trustworthy.

## What's Next

- Deploy private staging with `VERITAS_AUTH_TOKEN`.
- Add production-grade user authentication and multi-user case isolation.
- Add persistent database-backed case storage.
- Expand incident profiles and policy packs.
- Add evidence-bounded LLM summaries and audit brief drafting.
- Connect real containment systems only behind strict approval and rollback controls.

## Local Setup

```powershell
python -m pip install -r requirements.txt
python server.py
```

Open:

```text
http://127.0.0.1:5173
```

## Tests

```powershell
python smoke_tests.py
python browser_smoke_tests.py
python mcp_smoke_tests.py
python dashboard_mcp_route_tests.py
python deployment_security_tests.py
```

## Demo Video Outline

1. Problem: responders act before evidence thresholds are met.
2. Product: Veritas asks whether the team is justified to act.
3. Evidence intake: feed customer evidence or run the online Splunk evidence flow.
4. Decision readiness: show approved, caution, blocked, and not-ready states.
5. Missing SPL and blast radius: show why unsafe actions are blocked.
6. Approval and containment record: show safe simulated response.
7. Audit brief: show the final decision record.
