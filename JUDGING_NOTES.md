# Veritas AI Judging Notes

## Project Category

Primary track: **Security**

Bonus target: **Best Splunk Integration / MCP-ready workflow**

## Positioning

Veritas AI is a response decision assurance layer for Splunk.

Tagline: **Know when you have enough evidence to act.**

It is not:

- a generic SOC assistant
- a false-positive detector
- a normal SOAR automation demo

It answers:

"Before the team acts, has the required Splunk evidence threshold been met?"

## Why It Matters

Incident teams make risky decisions under pressure:

- disable the wrong account
- block the wrong IP
- declare no data accessed too early
- close an incident before containment is verified

Veritas makes those decisions evidence-bound and auditable.

## Differentiators

- Evidence Threshold Matrix
- Decision Readiness Score
- Missing Evidence To SPL
- Blast Radius Warning
- Evidence Integrity & Blind Spot Panel
- Real Splunk HEC ingestion path
- Live Splunk REST evidence pull
- One-click Judge Mode
- Analyst Approval Gate
- Evidence Drilldown
- Clickable functional detail pages
- Executable custom request runner for judge-provided evidence
- Decision Audit Brief with Splunk search provenance

## Security Maturity

Veritas explicitly states:

- Missing logs are not proof of safety.
- Logs are untrusted evidence, not instructions.
- High-impact actions require human approval.
- The demo uses deterministic evidence-bounded logic.

## Splunk Fit

The app uses Splunk-style evidence, HEC ingestion, REST search, and MCP-shaped tool-call output:

- `splunk.search`
- `splunk.notable_event`
- `splunk.risk_score`

It can run in `mock-mcp` mode for reliable judging, or in `splunk-rest` mode after:

- `python ingest_to_splunk.py`
- setting `SPLUNK_HOST`
- setting `SPLUNK_TOKEN`
- clicking **Pull indexed evidence**

For presentation, click **Run live judge demo** to execute the complete evidence -> decision -> containment -> audit flow.

Judges can also click any major indicator or navigation item to open a functional detail page, then feed their own incident facts into the custom request runner. Veritas recalculates readiness, blocks unsafe decisions, and simulates only approved containment.

Important wording: the default demo uses safe deterministic `mock-mcp` evidence. Optional Splunk REST and HEC ingestion are implemented for real indexed evidence. The backend boundary is designed for Splunk MCP Server integration, but the project should not claim live Splunk MCP Server calls unless that integration is added and verified.
