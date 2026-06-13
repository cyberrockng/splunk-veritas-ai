# Veritas AI Judging Notes

## Project Category

Primary track: **Security**

Bonus target: **Best Splunk Integration / MCP-enabled workflow**

## Positioning

Veritas AI is a **Tier 3 response decision assurance layer for Splunk**.

It answers:

"Before the team acts, has the required Splunk evidence threshold been met?"

Short value statement:

"Most SOC tools ask, 'Is this alert real?' Veritas asks, 'Are we justified to act?'"

## Why It Matters

Incident teams make risky decisions under pressure:

- disable the wrong account
- block the wrong IP
- declare no data accessed too early
- close an incident before containment is verified

Veritas makes those decisions evidence-bound and auditable.

## Differentiators

- Decision Readiness Strip
- Evidence Threshold Matrix
- Tier 3 incident queue
- Policy Builder with Standard, Strict, and Emergency modes
- Investigation Gaps to SPL
- Blast Radius & Decision Risk
- Evidence Integrity & Blind Spot Panel
- Analyst Approval Gate
- Evidence drilldown
- Tier 3 Decision Audit Brief with Splunk search provenance
- Security sandbox model that prevents untrusted feeds/files from becoming an exploit path into Splunk

## Security Maturity

Veritas explicitly states:

- Missing logs are not proof of safety.
- Logs are untrusted evidence, not instructions.
- External evidence is normalized through an allowlisted, size-limited data path before Splunk ingestion.
- Splunk tokens stay server-side and are never exposed to the browser.
- MCP write-capable HEC tools are disabled by default and require explicit enablement.
- High-impact actions require human approval.
- Demo containment is simulated and deterministic.
- Veritas does not detonate malware or execute suspicious files in this build.

## What Is Real vs Simulated

Real:

- Local Python API and frontend.
- Evidence threshold decision engine.
- Audit brief generation.
- Smoke tests.
- Optional Splunk HEC ingestion and Splunk REST search path.
- True stdio Splunk MCP server for REST search and HEC ingestion tools.
- Dashboard-to-MCP routing through the local Python API bridge.

Simulated:

- Default mock evidence for reliable judging without credentials.
- Containment actions, which are safe mock actions only.
- Direct browser-to-stdio MCP, because the local Python API is the MCP client bridge.

See `REAL_VS_SIMULATED.md` for the full boundary.

## Splunk Fit

The app uses Splunk-style evidence, HEC ingestion, REST search, and a separate stdio MCP server exposing real Splunk tools:

- `splunk.search`
- `splunk.veritas_evidence`
- `splunk.hec_ingest_event`
- `veritas.ingest_demo_evidence`

The default dashboard demo runs in safe `mock-mcp` mode with deterministic Splunk-style evidence. With Splunk configured, the dashboard backend routes indexed evidence searches through the real stdio MCP server by default. The precise claim is dashboard-to-local-API-to-MCP-to-Splunk; the browser does not directly launch stdio MCP.

For presentation, click **Run Live Judge Demo** to execute the evidence -> decision -> approval -> containment -> audit flow.

Judges can also click any major indicator or navigation item to open a functional detail page, then feed their own incident facts into the custom request runner. Veritas recalculates readiness, blocks unsafe decisions, and simulates only approved containment.
