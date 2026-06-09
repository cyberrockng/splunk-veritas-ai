# Splunk Veritas AI

Splunk Veritas AI is a real-time truth engine for digital operations. It checks claims made by humans or AI agents against Splunk evidence before teams make risky operational or security decisions.

## Problem

Incident rooms, SOC investigations, change reviews, and executive briefings are full of assumptions:

- "The database caused it."
- "No users are affected."
- "No customer data was accessed."
- "Rollback is safe."
- "The backup completed successfully."

Wrong assumptions waste response time and can create legal, security, operational, and trust risk.

## Solution

Veritas AI creates a Truth Card for every claim:

- Verdict: supported, contradicted, uncertain, or pending
- Confidence score
- Splunk evidence links
- Missing evidence
- Risk if the claim is wrong
- Recommended next action

The current MVP uses synthetic Splunk-style data for a hospital patient portal incident. The architecture is designed so the local evidence adapter can be replaced by Splunk MCP Server or Splunk SDK searches.

## Hackathon Fit

This project aligns with the Splunk Agentic Ops Hackathon by using AI-style agentic verification workflows to enhance security operations and observability decision-making with Splunk data.

Best-fit track: **Security**

Bonus prize target: **Best Use of Splunk MCP Server**

## Run Locally

No build step is required.

```powershell
python -m http.server 5173
```

Then open:

```text
http://localhost:5173
```

## Demo Flow

1. Open the War Room Truth Board.
2. Click **Verify claims**.
3. Show how Veritas contradicts dangerous assumptions:
   - Database caused the outage
   - No patients are affected
   - Rollback is safe
4. Add a new custom claim such as `The vendor caused this`.
5. Click **Export brief** to generate an evidence-backed decision brief.

## Future Splunk Integration

Planned production integrations:

- Splunk MCP Server for AI-agent access to Splunk searches
- Splunk AI Assistant for SPL generation and search explanation
- Splunk AI Toolkit for anomaly detection and confidence scoring
- Splunk Hosted Models for timeline summarization and risk classification
- Splunk dashboards or custom app packaging for in-platform deployment

## Repository Contents

- `index.html` - App shell and UI structure
- `styles.css` - Responsive dashboard styling
- `app.js` - Claim verification engine and synthetic evidence adapter
- `sample_splunk_events.json` - Demo evidence dataset
- `architecture_diagram.md` - Data flow and component architecture
- `LICENSE` - Open source license
