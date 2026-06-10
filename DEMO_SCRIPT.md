# Veritas AI Two-Minute Demo Script

## 0:00 - 0:20: Positioning

"Veritas AI is an Evidence Threshold Engine for Splunk. It does not just detect alerts or automate playbooks. It checks whether the team has enough evidence to safely make a response decision."

Point to:

- Know when you have enough evidence to act
- Decision Risk
- Principles panel

## 0:20 - 0:45: Run Judge Mode

Click **Run live judge demo**.

Say:

"The incident is an admin account takeover. Judge Mode pulls indexed events from Splunk, evaluates evidence thresholds, executes only evidence-ready containment, and opens the audit brief. If Splunk is unavailable, it falls back to the deterministic demo path."

Show:

- Evidence events loaded
- Timeline
- Telemetry completeness
- Provider badge: `mock-mcp` or `splunk-rest`

## 0:45 - 1:20: Check Thresholds

Point to the Evidence Threshold Matrix and Live Decision Spotlight.

Say:

"Veritas evaluates five proposed response decisions. It approves or cautions containment actions, but blocks unsafe statements when evidence is missing or contradictory."

Show:

- Revoke session token: Approved
- Disable admin account: Approved or Caution
- Block source IP: Caution
- Declare no sensitive data accessed: Blocked
- Close incident as contained: Not Ready or Blocked
- Click any **Evidence** button to show matched Splunk events, SPL, and job IDs

## 1:20 - 1:40: Execute Only Evidence-Ready Actions

Say:

"Veritas does not blindly automate every action. The analyst approval gate records approval before containment executes, then Veritas keeps blocking premature closure and no-data-access statements."

Show:

- Analyst Approval Gate
- Risk score drops after containment
- Live Decision Spotlight remains blocked for unsafe statements
- Close incident still needs post-containment monitoring

## 1:40 - 1:55: Explain The Differentiator

Say:

"This is not false-positive detection. The question is not just whether the alert is valid. The question is whether the response decision is justified by evidence."

Show:

- Evidence Threshold Matrix
- Missing Evidence To SPL
- Evidence Integrity & Blind Spot Panel
- MCP-shaped tool calls in the audit console
- Splunk job IDs when running in real Splunk mode

## 1:55 - 2:00: Export Brief

Say:

"The output is an auditable decision brief: what was approved, what was blocked, why, which Splunk jobs supported the decision, what evidence is missing, and what SPL should be run next."
