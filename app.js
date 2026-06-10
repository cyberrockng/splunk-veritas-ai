const riskScore = document.querySelector("#riskScore");
const riskSummary = document.querySelector("#riskSummary");
const stageLabel = document.querySelector("#stageLabel");
const providerLabel = document.querySelector("#providerLabel");
const eventCount = document.querySelector("#eventCount");
const readyCount = document.querySelector("#readyCount");
const blockedCount = document.querySelector("#blockedCount");
const telemetryScore = document.querySelector("#telemetryScore");
const startAttackBtn = document.querySelector("#startAttackBtn");
const nextEventBtn = document.querySelector("#nextEventBtn");
const loadSplunkBtn = document.querySelector("#loadSplunkBtn");
const investigateBtn = document.querySelector("#investigateBtn");
const resetLabBtn = document.querySelector("#resetLabBtn");
const exportBriefBtn = document.querySelector("#exportBriefBtn");
const executeSafeBtn = document.querySelector("#executeSafeBtn");
const labStatus = document.querySelector("#labStatus");
const demoSteps = document.querySelector("#demoSteps");
const decisionSpotlight = document.querySelector("#decisionSpotlight");
const decisionMatrix = document.querySelector("#decisionMatrix");
const integrityPanel = document.querySelector("#integrityPanel");
const splGapList = document.querySelector("#splGapList");
const eventStream = document.querySelector("#eventStream");
const runConsole = document.querySelector("#runConsole");
const briefDialog = document.querySelector("#briefDialog");
const closeBriefBtn = document.querySelector("#closeBriefBtn");
const briefOutput = document.querySelector("#briefOutput");

let state = {
  stage: "idle",
  events: [],
  detections: [],
  decisions: [],
  integrity: {},
  risk: 12,
  integration: { provider: "mock-mcp" },
};

let runLog = [
  {
    type: "ready",
    title: "Ready",
    detail: "Load incident evidence, then check whether each proposed response decision is evidence-ready.",
  },
];

const actionPlan = [
  {
    decisionId: "revoke-session",
    actionId: "revoke-token",
  },
  {
    decisionId: "disable-admin",
    actionId: "disable-account",
  },
  {
    decisionId: "block-source-ip",
    actionId: "block-ip",
  },
];

async function requestJson(path, options = {}) {
  const response = await fetch(path, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });

  if (!response.ok) {
    let message = `Request failed: ${response.status}`;
    try {
      const errorBody = await response.json();
      message = errorBody.error || message;
    } catch {
      // Keep the generic HTTP message.
    }
    throw new Error(message);
  }

  return response.json();
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function setState(nextState) {
  state = nextState;
  render();
}

function statusClass(status) {
  return String(status || "").toLowerCase().replace(/\s+/g, "-");
}

function severityClass(value) {
  return String(value || "").toLowerCase();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function riskText(score) {
  if (score >= 80) return "Critical response risk. Unsafe decisions must be blocked.";
  if (score >= 55) return "High response risk. Evidence supports containment, but statements need care.";
  if (score >= 30) return "Moderate response risk. Some decisions are ready, others need more evidence.";
  return "Low risk state. Continue monitoring and preserve evidence.";
}

function logEntry(type, title, detail) {
  runLog = [{ type, title, detail }, ...runLog].slice(0, 24);
}

function completedActions() {
  return new Set((state.actions || []).filter((item) => item.status === "completed").map((item) => item.id));
}

function completedActionCount() {
  return completedActions().size;
}

function hasCheckedThresholds() {
  return state.stage === "investigated" || state.stage === "responding" || completedActionCount() > 0;
}

function demoStepState(step) {
  const checks = {
    load: state.events.length === 6,
    check: hasCheckedThresholds(),
    act: completedActionCount() >= 3,
    brief: briefDialog.open,
  };

  if (checks[step]) return "done";
  if (step === "load" && state.events.length > 0) return "active";
  if (step === "check" && checks.load) return "active";
  if (step === "act" && checks.check) return "active";
  if (step === "brief" && checks.act) return "active";
  return "pending";
}

function renderMetrics() {
  const approved = state.decisions.filter((item) =>
    ["Approved", "Caution"].includes(item.status),
  ).length;
  const blocked = state.decisions.filter((item) =>
    ["Blocked", "Not Ready"].includes(item.status),
  ).length;

  riskScore.textContent = state.risk;
  riskSummary.textContent = riskText(state.risk);
  stageLabel.textContent = `Stage: ${state.stage}`;
  providerLabel.textContent = `Provider: ${state.integration?.provider || "mock-mcp"} / index=${state.integration?.index || "veritas"}`;
  eventCount.textContent = state.events.length;
  readyCount.textContent = approved;
  blockedCount.textContent = blocked;
  telemetryScore.textContent = `${state.integrity?.telemetry_completeness || 0}%`;
}

function renderDemoSteps() {
  const steps = [
    {
      id: "load",
      label: "Load evidence",
      detail: "Stream demo evidence or pull indexed events from Splunk.",
    },
    {
      id: "check",
      label: "Check thresholds",
      detail: "Score each proposed response decision against required evidence.",
    },
    {
      id: "act",
      label: "Execute safe actions",
      detail: "Run containment only for decisions that are evidence-ready.",
    },
    {
      id: "brief",
      label: "Export brief",
      detail: "Produce the audit-ready decision record.",
    },
  ];

  demoSteps.innerHTML = steps
    .map(
      (step, index) => `
        <article class="demo-step ${demoStepState(step.id)}">
          <span>${index + 1}</span>
          <div>
            <strong>${step.label}</strong>
            <p>${step.detail}</p>
          </div>
        </article>
      `,
    )
    .join("");
}

function spotlightDecision() {
  const dataAccess = state.decisions.find((item) => item.id === "declare-no-data-access");
  const closeIncident = state.decisions.find((item) => item.id === "close-contained");
  const disableAdmin = state.decisions.find((item) => item.id === "disable-admin");
  return dataAccess || closeIncident || disableAdmin || state.decisions[0];
}

function renderDecisionSpotlight() {
  if (!state.events.length) {
    decisionSpotlight.innerHTML = `
      <article class="spotlight-card">
        <span class="status-pill not-ready">Waiting</span>
        <div>
          <h4>No evidence loaded yet</h4>
          <p>Load the incident evidence and check thresholds to see Veritas approve safe containment while blocking unsafe statements.</p>
        </div>
      </article>
    `;
    return;
  }

  const decision = spotlightDecision();
  if (!decision) {
    decisionSpotlight.innerHTML = `
      <article class="spotlight-card">
        <span class="status-pill not-ready">Waiting</span>
        <div>
          <h4>No decision evaluated yet</h4>
          <p>Load the evidence and check thresholds to see Veritas approve safe containment while blocking unsafe statements.</p>
        </div>
      </article>
    `;
    return;
  }

  const evidenceHits = decision.checks?.filter((item) => item.status !== "missing").length || 0;
  const missing = decision.missing_evidence?.length || 0;
  const topGap = decision.missing_evidence?.[0];
  decisionSpotlight.innerHTML = `
    <article class="spotlight-card ${statusClass(decision.status)}">
      <span class="status-pill ${statusClass(decision.status)}">${decision.status}</span>
      <div>
        <h4>${escapeHtml(decision.title)}</h4>
        <p>${escapeHtml(decision.reason)}</p>
        <div class="spotlight-stats">
          <span>Readiness <strong>${decision.readiness}%</strong></span>
          <span>Evidence hits <strong>${evidenceHits}</strong></span>
          <span>Missing/unsafe <strong>${missing}</strong></span>
        </div>
        <p class="spotlight-action"><strong>Safe next action:</strong> ${escapeHtml(decision.recommended_action)}</p>
        ${
          topGap
            ? `<code>${escapeHtml(topGap.spl)}</code>`
            : `<code>All required evidence for this decision is currently present.</code>`
        }
      </div>
    </article>
  `;
}

function renderDecisionMatrix() {
  decisionMatrix.innerHTML = state.decisions
    .map(
      (decision) => `
        <article class="decision-card ${statusClass(decision.status)}">
          <div class="decision-card-header">
            <div>
              <h4>${decision.title}</h4>
              <p>${decision.description}</p>
            </div>
            <span class="status-pill ${statusClass(decision.status)}">${decision.status}</span>
          </div>
          <div class="decision-meta">
            <span>Readiness: <strong>${decision.readiness}%</strong></span>
            <span>Impact: <strong>${decision.impact}</strong></span>
            <span>Human approval: <strong>${decision.human_approval ? "Required" : "Optional"}</strong></span>
          </div>
          <p class="decision-reason">${decision.reason}</p>
          <div class="checklist">
            ${decision.checks
              .map(
                (check) => `
                  <div class="check-row ${check.status}">
                    <span>${check.status === "found" ? "Found" : check.status === "contradicted" ? "Contradicts" : "Missing"}</span>
                    <strong>${check.label}</strong>
                  </div>
                `,
              )
              .join("")}
          </div>
          <div class="guardrail-box">
            <strong>Blast radius:</strong> ${decision.blast_radius}
          </div>
          <p class="decision-action"><strong>Safe next action:</strong> ${decision.recommended_action}</p>
        </article>
      `,
    )
    .join("");
}

function renderIntegrity() {
  const integrity = state.integrity || {};
  integrityPanel.innerHTML = `
    <article>
      <span class="metric-label">Evidence Freshness</span>
      <strong>${integrity.freshness || "No events streamed"}</strong>
    </article>
    <article>
      <span class="metric-label">Splunk Contract</span>
      <strong>${state.integration?.incident_id || "INC-001"}</strong>
      <p>index=${state.integration?.index || "veritas"}, sourcetype=${state.integration?.sourcetype || "veritas:incident"}</p>
    </article>
    <article>
      <span class="metric-label">Sources Checked</span>
      <strong>${(integrity.sources_checked || []).length}</strong>
      <p>${(integrity.sources_checked || []).join(", ") || "None yet"}</p>
    </article>
    <article>
      <span class="metric-label">Sources Missing</span>
      <strong>${(integrity.sources_missing || []).length}</strong>
      <p>${(integrity.sources_missing || []).join(", ") || "None"}</p>
    </article>
    <article>
      <span class="metric-label">AI Safety</span>
      <strong>Evidence-bounded</strong>
      <p>${integrity.prompt_injection_warning || ""}</p>
    </article>
    <article class="wide">
      <span class="metric-label">Missing Telemetry Warning</span>
      <strong>Do not confuse absence with safety</strong>
      <p>${integrity.missing_telemetry_warning || ""}</p>
    </article>
    <article class="wide">
      <span class="metric-label">Approval Model</span>
      <strong>Human approval required</strong>
      <p>${integrity.human_approval_requirement || ""}</p>
    </article>
  `;
}

function renderSplGaps() {
  const gaps = state.decisions.flatMap((decision) =>
    decision.missing_evidence.map((item) => ({
      decision: decision.title,
      label: item.label,
      spl: item.spl,
    })),
  );

  if (!gaps.length) {
    splGapList.innerHTML = `<article class="timeline-item"><strong>No missing evidence gaps</strong><p>All current threshold checks have evidence.</p></article>`;
    return;
  }

  splGapList.innerHTML = gaps
    .slice(0, 8)
    .map(
      (gap) => `
        <article class="timeline-item">
          <strong>${gap.label}</strong>
          <p>${gap.decision}</p>
          <code>${gap.spl}</code>
        </article>
      `,
    )
    .join("");
}

function renderEvents() {
  if (!state.events.length) {
    eventStream.innerHTML = `<article class="evidence-item"><p>No evidence loaded yet.</p></article>`;
    return;
  }

  eventStream.innerHTML = state.events
    .slice()
    .reverse()
    .map(
      (event) => `
        <article class="evidence-item ${severityClass(event.severity)}">
          <div class="evidence-item-header">
            <strong>${event.id} - ${event.time}</strong>
            <span class="severity-pill ${severityClass(event.severity)}">${event.severity}</span>
          </div>
          <span>${event.source}${event.origin ? ` / ${event.origin}` : ""}</span>
          <code>${event.query}</code>
          ${event.splunk_job_id ? `<small>Splunk job: ${event.splunk_job_id}</small>` : ""}
          <p>${event.summary}</p>
        </article>
      `,
    )
    .join("");
}

function renderRunConsole() {
  runConsole.innerHTML = runLog
    .map(
      (entry) => `
        <article class="run-entry ${entry.type}">
          <strong>${entry.title}</strong>
          <p>${entry.detail}</p>
        </article>
      `,
    )
    .join("");
}

function render() {
  renderMetrics();
  renderDemoSteps();
  renderDecisionSpotlight();
  renderDecisionMatrix();
  renderIntegrity();
  renderSplGaps();
  renderEvents();
  renderRunConsole();
  executeSafeBtn.disabled = !hasCheckedThresholds() || completedActionCount() >= 3;
}

async function loadState() {
  setState(await requestJson("/api/sentinel/state"));
}

async function resetLab() {
  const nextState = await requestJson("/api/sentinel/reset", { method: "POST" });
  runLog = [
    {
      type: "ready",
      title: "Lab reset",
      detail: "Evidence has been cleared. Load the incident evidence to evaluate decisions.",
    },
  ];
  labStatus.textContent = "Reset complete";
  setState(nextState);
}

async function streamNextEvent() {
  const previousCount = state.events.length;
  const nextState = await requestJson("/api/sentinel/step", { method: "POST" });
  const event = nextState.events[nextState.events.length - 1];
  if (event && nextState.events.length > previousCount) {
    logEntry("search", `Loaded ${event.id}`, event.summary);
  }
  labStatus.textContent =
    nextState.stage === "attack-complete" ? "Evidence load complete" : "Evidence event loaded";
  setState(nextState);
}

async function loadFromSplunk() {
  labStatus.textContent = "Pulling indexed evidence";
  try {
    const result = await requestJson("/api/sentinel/load-splunk", { method: "POST" });
    const search = result.search || {};
    runLog = [
      {
        type: "tool",
        title: "Loaded indexed Splunk evidence",
        detail: `job=${search.job_id}, mapped=${search.mapped_events}, missing=${(search.missing_events || []).join(", ") || "none"}`,
      },
      {
        type: "search",
        title: "Live SPL",
        detail: search.query || "No query returned.",
      },
      ...runLog,
    ].slice(0, 24);
    labStatus.textContent = `${search.mapped_events || 0} indexed events loaded`;
    setState(result);
  } catch (error) {
    labStatus.textContent = error.message;
    logEntry("error", "Splunk pull failed", error.message);
    render();
  }
}

async function startAttack() {
  const started = await requestJson("/api/sentinel/start", { method: "POST" });
  runLog = [
    {
      type: "claim",
      title: "Incident evidence loading",
      detail: "Veritas is loading the admin takeover evidence set from Splunk-style telemetry.",
    },
  ];
  labStatus.textContent = "Loading evidence";
  setState(started);

  for (let index = 0; index < started.sequence_length; index += 1) {
    await sleep(420);
    await streamNextEvent();
  }
}

async function checkThresholds() {
  labStatus.textContent = "Checking thresholds";
  const result = await requestJson("/api/sentinel/investigate", { method: "POST" });

  logEntry("claim", "Evidence threshold check complete", result.summary);
  result.tool_calls.forEach((call) => {
    const resultText =
      call.tool === "splunk.search"
        ? `provider=${call.result.provider}, job=${call.result.job_id}, results=${call.result.result_count}, link=${call.result.link}${
            call.result.error ? `, fallback=${call.result.error}` : ""
          }`
        : JSON.stringify(call.result);
    logEntry("tool", `MCP ${call.tool}`, `${JSON.stringify(call.arguments)} => ${resultText}`);
  });
  result.decisions.forEach((decision) => {
    logEntry(
      statusClass(decision.status) === "approved" ? "supported" : statusClass(decision.status),
      `${decision.title}: ${decision.status}`,
      `Readiness ${decision.readiness}%. ${decision.reason}`,
    );
  });

  labStatus.textContent = `${result.decisions.length} decisions evaluated`;
  setState(result);
}

async function executeApprovedContainment() {
  if (!hasCheckedThresholds()) {
    labStatus.textContent = "Check thresholds first";
    return;
  }

  labStatus.textContent = "Executing approved containment";
  let nextState = state;
  const completed = completedActions();
  const allowedStatuses = new Set(["Approved", "Caution"]);

  for (const item of actionPlan) {
    const decision = nextState.decisions.find((candidate) => candidate.id === item.decisionId);
    if (!decision || !allowedStatuses.has(decision.status) || completed.has(item.actionId)) {
      continue;
    }

    nextState = await requestJson("/api/sentinel/respond", {
      method: "POST",
      body: JSON.stringify({ action: item.actionId }),
    });
    const action = nextState.actions.find((candidate) => candidate.id === item.actionId);
    logEntry("supported", `Executed ${action?.label || item.actionId}`, action?.summary || "Containment action completed.");
    setState(nextState);
    await sleep(220);
  }

  const refreshed = await requestJson("/api/sentinel/investigate", { method: "POST" });
  logEntry(
    "blocked",
    "Unsafe closure still blocked",
    "Containment actions lowered risk, but Veritas still requires post-containment monitoring before closing the incident.",
  );
  labStatus.textContent = "Containment executed";
  setState(refreshed);
}

async function exportBrief() {
  const data = await requestJson("/api/sentinel/brief");
  briefOutput.textContent = data.brief;
  briefDialog.showModal();
  render();
}

startAttackBtn.addEventListener("click", startAttack);
nextEventBtn.addEventListener("click", streamNextEvent);
loadSplunkBtn.addEventListener("click", loadFromSplunk);
investigateBtn.addEventListener("click", checkThresholds);
resetLabBtn.addEventListener("click", resetLab);
exportBriefBtn.addEventListener("click", exportBrief);
executeSafeBtn.addEventListener("click", executeApprovedContainment);
closeBriefBtn.addEventListener("click", () => briefDialog.close());

loadState();
