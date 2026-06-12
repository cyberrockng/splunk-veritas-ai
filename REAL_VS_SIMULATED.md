# What Is Real vs Simulated

This project is intentionally explicit about what is real, what is simulated, and what is future integration work. The goal is to give judges a strong demo without overstating the implementation.

## Real In This Repository

| Area | Status |
| --- | --- |
| Local app | Real local Python server and browser-based frontend. |
| Evidence threshold engine | Real deterministic decision logic in `server.py`. |
| Decision readiness | Real scoring and status calculation for Approved, Caution, Blocked, and Not Ready decisions. |
| Evidence matrix | Real mapping between required evidence, found evidence, missing evidence, and SPL gaps. |
| Detail pages | Real functional pages for risk, decisions, matrix, integrity, missing evidence, blast radius, audit, and timeline. |
| Custom request runner | Real local endpoint that evaluates a request against the current evidence state. |
| Audit brief | Real generated Tier 3 decision record with provider, timestamp, readiness, evidence, missing SPL, blast radius, and recommended next action. |
| Smoke tests | Real automated smoke tests in `smoke_tests.py`. |
| HEC ingestion | Real Splunk HTTP Event Collector ingestion through `ingest_to_splunk.py`. |
| Splunk REST loading | Real optional Splunk REST search path when credentials and indexed events are configured. |
| Splunk proof screenshots | Real local screenshots captured after HEC ingestion and Splunk REST loading. |

## Real When Splunk Is Configured

When Splunk environment variables are present and valid, Veritas can:

- Send demo evidence to Splunk through HEC.
- Search indexed evidence through Splunk REST.
- Load Splunk events into the decision engine.
- Show `provider: splunk-rest`.
- Show `Mode: Real indexed evidence`.
- Include the Splunk search job ID and query in the audit trail.

The captured proof in `assets/` shows this path working locally.

## Simulated By Design

| Area | Why it is simulated |
| --- | --- |
| Default evidence mode | The project defaults to deterministic `mock-mcp` evidence so judges can run the demo without Splunk credentials. |
| Containment execution | Account disable, token revoke, and IP block are safe simulated actions. No destructive security action is performed. |
| Risk reduction | Residual risk changes are simulated to demonstrate workflow impact after approved mock containment. |
| MCP integration | The project emits integration-ready Splunk tool labels, but it does not claim live Splunk MCP Server calls. |
| AI behavior | The product name includes AI, but the current decision engine is deterministic and evidence-bounded. It does not run an autonomous unbounded AI agent. |

## Not Implemented Yet

- Live Splunk MCP Server calls.
- Real destructive containment against identity, firewall, endpoint, or cloud systems.
- Production authentication and multi-user state isolation.
- Production deployment of the Python API.
- AI/LLM-generated decisions.

## Demo Language To Use

Use this wording:

> Veritas has a real local decision engine, real HEC ingestion, and a real optional Splunk REST search path. The default demo evidence and containment actions are simulated for safety and judging reliability.

## Demo Language To Avoid

Avoid these claims unless the implementation is added and verified:

- "It uses the live Splunk MCP Server."
- "It performs real containment."
- "The AI autonomously decides and acts."
- "It is production deployed."
- "Missing logs prove the environment is safe."

## Safety Principle

Missing evidence is uncertainty, not proof of safety. Veritas blocks unsafe conclusions until the required evidence threshold is met.
