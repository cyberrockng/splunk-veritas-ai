# Veritas AI Roadmap

## Passed: Phase 1 - Evidence Backend

- Synthetic Splunk-style admin takeover evidence.
- MCP-shaped search envelopes.
- Optional Splunk REST configuration path.
- Deterministic backend logic for reliable demos.

## Passed: Phase 2 - Evidence Threshold Engine

- Five proposed response decisions.
- Required evidence checklist per decision.
- Readiness score.
- Status: Approved, Caution, Blocked, Not Ready.
- Missing evidence to SPL.
- Blast-radius warnings.

## Passed: Phase 3 - Evidence Integrity & Blind Spots

- Evidence freshness.
- Sources checked.
- Sources missing.
- Telemetry completeness.
- Prompt-injection safety warning.
- Missing telemetry warning.
- Human approval requirement.

## Passed: Phase 4 - Decision Audit Brief

- Exports decision readiness.
- Includes missing evidence and SPL queries.
- Includes detections, evidence timeline, and safety warnings.

## Passed: Phase 5 - Submission Polish

- Judge demo runway added to the first screen.
- Live decision spotlight added.
- Evidence-gated containment execution added.
- Demo script updated around evidence -> decision -> action -> audit.
- Smoke tests cover post-action decision state.

## Passed: Phase 6 - Real Splunk Data Path

- Added HEC ingestion script for Splunk.
- Added real-data runbook.
- Added `/api/sentinel/load-splunk` evidence loader.
- Added **Pull indexed evidence** UI action.
- Added `splunk-rest` provider/index/incident visibility in the UI.
- Keep `mock-mcp` fallback for judging reliability.

## Passed: Phase 7 - Real Splunk Runtime Validation

- Create or access a Splunk instance.
- Create `veritas` index and HEC token.
- Run `python ingest_to_splunk.py`.
- Start Veritas with `SPLUNK_HOST` and `SPLUNK_TOKEN`.
- Pull indexed evidence from the UI and confirm real job IDs.

## Passed: Phase 8 - Judge Mode & Audit Provenance

- Added **Run live judge demo** one-click flow.
- Judge Mode pulls indexed evidence, checks thresholds, executes safe containment, and opens the brief.
- Audit brief now groups approved/caution and blocked/not-ready decisions.
- Audit brief includes Splunk index, incident id, evidence load job, evidence event jobs, threshold search jobs, and source coverage.

## Passed: Phase 9 - Approval Gate & Evidence Drilldown

- Added analyst approve/reject workflow before containment actions execute.
- Backend now blocks high-impact response actions until approval is recorded.
- Added evidence drilldown for each threshold checklist item.
- Drilldown shows SPL, matched events, source, user, IP, and Splunk job context.
- UI/UX upgraded around the approval and drilldown workflow.

## Current: Phase 10 - Submission Package

- Capture screenshots or short GIF.
- Record two-minute walkthrough.
- Prepare final Devpost copy.
- Add sample Splunk data ingestion notes.
