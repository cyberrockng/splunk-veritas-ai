# Architecture Diagram

```mermaid
flowchart LR
  subgraph Sources["Operational Evidence Sources"]
    A["Splunk Auth Logs"]
    B["Splunk APM and Metrics"]
    C["Deployment Events"]
    D["Backup Validation Logs"]
    E["Support and Impact Events"]
  end

  subgraph Splunk["Splunk Platform"]
    F["Indexes and Saved Searches"]
    G["Splunk MCP Server"]
    H["Splunk AI Assistant for SPL"]
    I["Splunk AI Toolkit and Hosted Models"]
  end

  subgraph Veritas["Splunk Veritas AI"]
    J["Claim Intake"]
    K["Evidence Retrieval Agent"]
    L["Truth Verification Engine"]
    M["Risk and Confidence Scorer"]
    N["Truth Cards"]
    O["Decision Brief Generator"]
  end

  subgraph Users["Users and Workflows"]
    P["Incident Commander"]
    Q["SOC Analyst"]
    R["SRE or Developer"]
    S["Executive or Auditor"]
  end

  A --> F
  B --> F
  C --> F
  D --> F
  E --> F
  F --> G
  G --> K
  H --> K
  I --> M
  J --> K
  K --> L
  L --> M
  M --> N
  N --> O
  N --> P
  N --> Q
  N --> R
  O --> S
```

## Data Flow

1. Users or AI agents submit claims from a war room, SOC queue, change review, or incident thread.
2. Veritas AI converts each claim into evidence questions and SPL search intents.
3. Splunk MCP Server retrieves relevant events, metrics, traces, deployment records, and security logs.
4. The verification engine classifies each claim as supported, contradicted, uncertain, or untestable.
5. The risk scorer estimates confidence and the cost of acting on a false claim.
6. The UI presents Truth Cards with direct evidence links and recommended next actions.
7. The brief generator produces an evidence-backed report for leaders, auditors, and incident records.
