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

## Current: Phase 7 - Real Splunk Runtime Validation

- Create or access a Splunk instance.
- Create `veritas` index and HEC token.
- Run `python ingest_to_splunk.py`.
- Start Veritas with `SPLUNK_HOST` and `SPLUNK_TOKEN`.
- Pull indexed evidence from the UI and confirm real job IDs.

## Next: Phase 8 - Submission Package

- Capture screenshots or short GIF.
- Record two-minute walkthrough.
- Prepare final Devpost copy.
- Add sample Splunk data ingestion notes.
