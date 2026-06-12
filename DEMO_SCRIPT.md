# Veritas AI Under-Three-Minute Demo Script

## 0:00 - 0:20: Problem

"During incidents, teams often act before the evidence threshold is met. They may disable the wrong admin, block a shared IP, declare no data accessed too early, or close an incident while attacker activity remains unresolved."

Point to the tagline:

**Know when you have enough evidence to act.**

## 0:20 - 0:40: Product

"Veritas AI is a Tier 3 response decision assurance layer for Splunk. It checks whether the team has enough Splunk evidence before approving high-impact incident-response decisions."

Optional honesty note:

"For safety, the containment actions in this demo are simulated. The evidence engine is real, and the Splunk-backed path can ingest through HEC and load indexed evidence through Splunk REST."

Show:

- Residual Risk Score
- Decision Readiness Strip
- Tier 3 incident/policy controls

## 0:40 - 1:05: Start Incident

Click **Run Live Judge Demo**.

Say:

"The scenario is an admin account takeover: impossible travel, MFA anomaly, privilege escalation, admin API access, scripted download, and cloud export."

Show the **Attack Path Timeline**.

## 1:05 - 1:35: Decision Assurance

Point to the **Decision Readiness Strip** and **Evidence Threshold Matrix**.

Say:

"Veritas does not ask only whether the alert is real. It asks whether we are justified to act."

Show:

- Revoke session token approved when active session risk is present
- Disable admin account requires human approval
- Block source IP is caution because of blast radius
- No-data-access and incident-closed conclusions remain blocked

## 1:35 - 2:05: Gaps, Approval, And Containment

Show **Investigation Gaps to SPL**.

Say:

"For every missing evidence item, Veritas gives the SPL needed to close the gap."

Then show:

- Human approval requirement
- Execute approved mock containment
- Residual risk drops only after approved containment
- Unsafe conclusions remain blocked

## 2:05 - 2:40: Audit Brief

Export the **Tier 3 Decision Audit Brief**.

Say:

"The output is a professional decision record: readiness, status, evidence found, evidence missing, SPL gaps, blast radius, approval state, provider, timestamp, and safety notes."

## Closing

"Veritas AI tells Tier 3 responders when they have enough evidence to act."
