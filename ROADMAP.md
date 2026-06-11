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

## Passed: Phase 4 - Tier 3 Decision Audit Brief

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

## Passed: Phase 10 - Executable Custom Runner & Detail Pages

- Added custom request runner for analyst-provided incident facts.
- Custom requests recalculate evidence, readiness, feedback, and safe execution.
- Added clickable functional detail pages for risk, decisions, matrix, integrity, missing evidence, blast radius, audit, and timeline.
- Detail pages can refresh state, run custom requests, approve/execute eligible actions, and export briefs.

## Passed: Phase 11 - Submission Package

- Capture screenshots or short GIF.
- Record two-minute walkthrough.
- Prepare final Devpost copy.
- Add sample Splunk data ingestion notes.

## Current: Phase 12 - Deployment Readiness

- Add `.env.example` without secrets.
- Keep local `python server.py` demo reliable.
- Add health check response for deployment monitors.
- Prepare safe `vercel.json` without deploying.
- Document Vercel options and stop before actual deployment.
- Keep mock mode as the deterministic default when Splunk is not configured.

## Passed: Phase 13 - Tier 3 Response Governance

- Added incident queue with multiple selectable incident profiles.
- Added policy builder with Standard, Strict, and Emergency evidence governance modes.
- Policy profile affects readiness scoring and approval/caution behavior.
- Added decision simulation summary to show how evidence and policy affect action readiness.
- Smoke tests cover incident catalog, profile switching, and policy switching.

## Next: Phase 14 - Tier 3 Expansion

- Add distinct evidence packs for ransomware, insider risk, and cloud key compromise.
- Add editable checklist weights and mandatory/optional threshold toggles.
- Add an audit archive for prior incident runs.
