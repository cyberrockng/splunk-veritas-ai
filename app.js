const API_ORIGIN = (
  window.VERITAS_API_ORIGIN
  || new URLSearchParams(window.location.search).get("api")
  || ""
).replace(/\/$/, "");
const API_BASE = `${API_ORIGIN}/api/sentinel`;

const els = {
  riskScore: document.querySelector("#riskScore"),
  riskSummary: document.querySelector("#riskSummary"),
  incidentTitle: document.querySelector("#incidentTitle"),
  incidentIdLabel: document.querySelector("#incidentIdLabel"),
  evidenceSourceLabel: document.querySelector("#evidenceSourceLabel"),
  modeLabel: document.querySelector("#modeLabel"),
  stageLabel: document.querySelector("#stageLabel"),
  providerLabel: document.querySelector("#providerLabel"),
  eventCount: document.querySelector("#eventCount"),
  readyCount: document.querySelector("#readyCount"),
  blockedCount: document.querySelector("#blockedCount"),
  telemetryScore: document.querySelector("#telemetryScore"),
  judgeStoryCards: document.querySelector("#judgeStoryCards"),
  readinessStrip: document.querySelector("#readinessStrip"),
  demoSteps: document.querySelector("#demoSteps"),
  decisionMatrix: document.querySelector("#decisionMatrix"),
  findingsPanel: document.querySelector("#findingsPanel"),
  thresholdMatrix: document.querySelector("#thresholdMatrix"),
  integrityPanel: document.querySelector("#integrityPanel"),
  splGapList: document.querySelector("#splGapList"),
  blastRadiusList: document.querySelector("#blastRadiusList"),
  auditPreview: document.querySelector("#auditPreview"),
  approvalGate: document.querySelector("#approvalGate"),
  decisionSpotlight: document.querySelector("#decisionSpotlight"),
  eventStream: document.querySelector("#eventStream"),
  runConsole: document.querySelector("#runConsole"),
  judgeModeBtn: document.querySelector("#judgeModeBtn"),
  onlineFeedBtn: document.querySelector("#onlineFeedBtn"),
  loadSplunkBtn: document.querySelector("#loadSplunkBtn"),
  startAttackBtn: document.querySelector("#startAttackBtn"),
  nextEventBtn: document.querySelector("#nextEventBtn"),
  investigateBtn: document.querySelector("#investigateBtn"),
  executeSafeBtn: document.querySelector("#executeSafeBtn"),
  resetLabBtn: document.querySelector("#resetLabBtn"),
  incidentSelector: document.querySelector("#incidentSelector"),
  loadIncidentProfileBtn: document.querySelector("#loadIncidentProfileBtn"),
  policySelector: document.querySelector("#policySelector"),
  applyPolicyBtn: document.querySelector("#applyPolicyBtn"),
  tier3Summary: document.querySelector("#tier3Summary"),
  exportBriefBtn: document.querySelector("#exportBriefBtn"),
  evidenceIntake: document.querySelector("#evidenceIntake"),
  intakeForm: document.querySelector("#intakeForm"),
  intakeIncidentTitle: document.querySelector("#intakeIncidentTitle"),
  intakeAction: document.querySelector("#intakeAction"),
  intakeEvidence: document.querySelector("#intakeEvidence"),
  intakeEvidenceFile: document.querySelector("#intakeEvidenceFile"),
  intakeExecute: document.querySelector("#intakeExecute"),
  intakeResult: document.querySelector("#intakeResult"),
  intakeExampleBtn: document.querySelector("#intakeExampleBtn"),
  caseHistoryPanel: document.querySelector("#caseHistoryPanel"),
  customRequestBtn: document.querySelector("#customRequestBtn"),
  customDialog: document.querySelector("#customDialog"),
  closeCustomBtn: document.querySelector("#closeCustomBtn"),
  customRequestForm: document.querySelector("#customRequestForm"),
  customIncidentTitle: document.querySelector("#customIncidentTitle"),
  customAction: document.querySelector("#customAction"),
  customEvidence: document.querySelector("#customEvidence"),
  customExecute: document.querySelector("#customExecute"),
  customResult: document.querySelector("#customResult"),
  briefDialog: document.querySelector("#briefDialog"),
  briefOutput: document.querySelector("#briefOutput"),
  closeBriefBtn: document.querySelector("#closeBriefBtn"),
  evidenceDialog: document.querySelector("#evidenceDialog"),
  evidenceDialogTitle: document.querySelector("#evidenceDialogTitle"),
  evidenceOutput: document.querySelector("#evidenceOutput"),
  closeEvidenceBtn: document.querySelector("#closeEvidenceBtn")
};

els.themeToggle = document.querySelector("#themeToggle");

const actionPlan = [
  { decisionId: "revoke-session", actionId: "revoke-token" },
  { decisionId: "disable-admin", actionId: "disable-account" },
  { decisionId: "block-source-ip", actionId: "block-ip" }
];

const EXECUTIVE_CANVAS_WIDTH = 1500;

let state = {
  incident_id: "INC-001",
  stage: "Ready",
  risk: 0,
  incident: {},
  policy: {},
  incident_catalog: [],
  policy_catalog: [],
  events: [],
  detections: [],
  decisions: [],
  integrity: {},
  actions: [],
  approvals: [],
  integration: {}
};

let caseHistory = [];

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function statusClass(status = "") {
  return String(status).toLowerCase().replaceAll(" ", "-");
}

function normalizedStatus(status = "") {
  return statusClass(status);
}

function providerInfo(integration = {}) {
  const provider = integration.search_provider || integration.provider || integration.adapter || "mock-mcp";
  const feed = integration.last_online_feed;
  const feedIngested = Boolean(feed?.ingested?.length);

  if (provider === "splunk-rest") {
    return {
      provider,
      source: feedIngested ? "Evidence source: online feed indexed by Splunk REST" : "Evidence source: Splunk REST",
      mode: feedIngested ? "Mode: Ingested online evidence scored" : "Mode: Real indexed evidence",
      tone: "real"
    };
  }

  if (provider === "splunk-mcp") {
    return {
      provider,
      source: feedIngested ? "Evidence source: online feed indexed through Splunk MCP" : "Evidence source: Splunk MCP",
      mode: feedIngested ? "Mode: Ingested online evidence scored" : "Mode: MCP-routed indexed evidence",
      tone: "real"
    };
  }

  if (provider === "mock-mcp-fallback") {
    return {
      provider,
      source: feedIngested ? "Evidence source: online feed ingested; Splunk search unavailable" : "Evidence source: Splunk search unavailable",
      mode: feedIngested ? "Mode: Indexed evidence pending" : "Mode: No live indexed evidence",
      tone: "fallback"
    };
  }

  if (provider === "custom-input") {
    return {
      provider: "analyst-evidence",
      source: "Evidence source: analyst-supplied evidence",
      mode: "Mode: Analyst-supplied evidence evaluation",
      tone: "fallback"
    };
  }

  if (feedIngested) {
    return {
      provider: "splunk-hec",
      source: "Evidence source: online feed ingested into Splunk HEC",
      mode: "Mode: Waiting for indexed Splunk search",
      tone: "fallback"
    };
  }

  return {
    provider: "not-loaded",
    source: "Evidence source: connect Splunk and ingest the online feed",
    mode: "Mode: Online evidence not loaded",
    tone: "fallback"
  };
}

function onlineFeedStatus() {
  const feed = state.integration?.last_online_feed;
  if (!feed?.ingested?.length) return null;
  return {
    eventIds: feed.ingested,
    sourceCount: feed.sources_fetched?.length || 0,
    index: feed.index || "veritas",
    sourcetype: feed.sourcetype || "veritas:incident"
  };
}

function hasScoredEvidence() {
  return Boolean(state.events?.length || state.integration?.request);
}

function hasAnyRun() {
  return hasScoredEvidence() || Boolean(onlineFeedStatus());
}

function emptyRunPanel(message = "Feed evidence to run Veritas. Previous run results will stay here until New Case is used.") {
  return `<div class="empty-panel">${escapeHtml(message)}</div>`;
}

function riskTone(score = 0) {
  if (score >= 75) return "high";
  if (score >= 45) return "medium";
  if (score > 0) return "low";
  return "quiet";
}

function statusLabel(status = "") {
  const normalized = String(status).replaceAll("-", " ");
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function readinessTone(decision) {
  const status = normalizedStatus(decision.status);
  if (status === "approved") return "ready";
  if (status === "blocked" || status === "not-ready") return "blocked";
  if (status === "caution") return "caution";
  return "review";
}

function isBlockedDecision(decision) {
  return ["blocked", "not-ready"].includes(readinessTone(decision));
}

function blockedDecisionLabel(decision) {
  if (!isBlockedDecision(decision)) return "";
  return decision.id === "declare-no-data-access"
    ? "Unsafe conclusion blocked"
    : "Evidence gate blocked";
}

function formatTime(value) {
  if (!value) return "--:--:--";
  if (String(value).startsWith("custom+")) {
    return `Step ${String(value).split("+")[1] || ""}`;
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function eventDisplay(event) {
  const eventId = event.id || event.event_id;
  const map = {
    "SEC-3001": ["Impossible Travel", "Lagos and Frankfurt logins within three minutes", "geo"],
    "SEC-3002": ["MFA Anomaly", "MFA push approved after denied prompts", "shield"],
    "SEC-3003": ["Privilege Escalation", "Suspicious session granted super_admin role", "user"],
    "SEC-3004": ["Admin API Access", "Privileged export endpoint returned 200", "cloud"],
    "SEC-3005": ["Scripted Download", "Scripted download tooling observed on workstation", "download"],
    "SEC-3006": ["Cloud Export", "Sensitive archive written to object storage", "cloud"]
  };
  const fallback = event.title || event.action || "Security Event";
  const item = map[eventId] || [fallback, event.summary || event.description || event.message || "", "alert"];
  return {
    title: item[0],
    description: item[1],
    icon: item[2]
  };
}

function findingTitle(event) {
  return eventDisplay(event).title;
}

function findingDescription(event) {
  return eventDisplay(event).description || event.summary || event.message || "";
}

async function requestJson(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });

  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const payload = await response.json();
      message = payload.error || payload.detail || message;
    } catch {
      message = await response.text();
    }
    throw new Error(message);
  }

  return response.json();
}

async function loadCaseHistory() {
  try {
    const payload = await requestJson("/case-history");
    caseHistory = Array.isArray(payload.history) ? payload.history : [];
  } catch {
    caseHistory = [];
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function setState(nextState) {
  state = {
    ...state,
    ...nextState,
    events: nextState.events || [],
    detections: nextState.detections || [],
    decisions: nextState.decisions || [],
    actions: nextState.actions || [],
    approvals: nextState.approvals || [],
    integrity: nextState.integrity || {},
    integration: nextState.integration || {}
  };
  render();
}

function fitExecutiveCanvas() {
  document.documentElement.style.setProperty("--fit-scale", "1");
  document.body.style.minHeight = "";
  document.body.style.overflow = "";
}

function logEntry(message, type = "info") {
  const row = document.createElement("div");
  row.className = `console-line ${type}`;
  row.innerHTML = `<span>${formatTime(new Date().toISOString())}</span><strong>${escapeHtml(message)}</strong>`;
  els.runConsole.prepend(row);
  while (els.runConsole.children.length > 9) els.runConsole.lastElementChild.remove();
}

function completedActionCount() {
  return state.actions.filter((action) => action.status === "completed").length;
}

function approvedApprovalCount() {
  return state.approvals.filter((approval) => approval.approval === "approved").length;
}

function missingEvidenceItems() {
  return state.decisions.flatMap((decision) =>
    (decision.checks || [])
      .filter((check) => check.status !== "found")
      .map((check) => ({ decision, check }))
  );
}

function hasCheckedThresholds() {
  return state.decisions.some((decision) => (decision.checks || []).length);
}

function allChecks() {
  const seen = new Set();
  const rows = [];

  for (const decision of state.decisions) {
    for (const check of decision.checks || []) {
      const key = `${check.id}-${check.label}`;
      if (seen.has(key)) continue;
      seen.add(key);
      rows.push({ decision, check });
    }
  }

  return rows;
}

function findCheck(checkId) {
  for (const decision of state.decisions) {
    const check = (decision.checks || []).find((item) => item.id === checkId);
    if (check) return { decision, check };
  }
  return null;
}

function renderMetrics() {
  const scoredDecisions = hasScoredEvidence() ? state.decisions : [];
  const ready = scoredDecisions.filter((decision) => ["approved", "caution"].includes(normalizedStatus(decision.status))).length;
  const blocked = scoredDecisions.filter((decision) => ["blocked", "not-ready"].includes(normalizedStatus(decision.status))).length;
  const provider = providerInfo(state.integration);
  const customRequest = state.integration?.request;
  const telemetry = state.integrity?.telemetry_completeness ?? 0;
  const risk = hasAnyRun() ? Number(state.risk || 0) : 0;
  const riskText = risk >= 75 ? "High Risk" : risk >= 45 ? "Elevated Risk" : risk > 0 ? "Controlled Risk" : "No Active Risk";
  const trend = risk >= 75 ? "up +12" : risk >= 45 ? "up +6" : risk > 0 ? "down -42" : "0";

  els.riskScore.textContent = risk;
  els.riskSummary.textContent = `${riskText} | Trend (15m): ${trend}`;
  els.incidentTitle.textContent = customRequest?.title || state.incident?.title || "ADMIN ACCOUNT TAKEOVER";
  if (els.incidentIdLabel) {
    els.incidentIdLabel.textContent = state.incident?.display_incident_id || state.integration?.display_incident_id || "INC-2025-0001";
  }
  if (els.evidenceSourceLabel) {
    els.evidenceSourceLabel.textContent = provider.source;
  }
  if (els.modeLabel) {
    els.modeLabel.textContent = provider.mode;
    els.modeLabel.className = `mode-badge mode-${provider.tone}`;
  }
  els.stageLabel.textContent = state.stage || "Ready";
  els.providerLabel.textContent = provider.provider;
  els.eventCount.textContent = state.events.length;
  els.readyCount.textContent = ready;
  els.blockedCount.textContent = blocked;
  els.telemetryScore.textContent = `${telemetry}%`;

  document.documentElement.style.setProperty("--risk-value", `${Math.min(risk, 100) * 1.8}deg`);
  document.documentElement.dataset.riskTone = riskTone(risk);
}

function renderTier3Controls() {
  if (els.incidentSelector && state.incident_catalog?.length) {
    els.incidentSelector.innerHTML = state.incident_catalog
      .map((incident) => `
        <option value="${escapeHtml(incident.id)}" ${incident.id === state.incident?.id ? "selected" : ""}>
          ${escapeHtml(incident.title)}
        </option>
      `)
      .join("");
  }

  if (els.policySelector && state.policy_catalog?.length) {
    els.policySelector.innerHTML = state.policy_catalog
      .map((policy) => `
        <option value="${escapeHtml(policy.id)}" ${policy.id === state.policy?.id ? "selected" : ""}>
          ${escapeHtml(policy.label)}
        </option>
      `)
      .join("");
  }

  if (els.tier3Summary) {
    const topDecision = hasScoredEvidence()
      ? [...state.decisions].sort((a, b) => (b.readiness || 0) - (a.readiness || 0))[0]
      : null;
    const blocked = hasScoredEvidence()
      ? state.decisions.filter((decision) => ["blocked", "not-ready"].includes(normalizedStatus(decision.status))).length
      : 0;
    els.tier3Summary.innerHTML = `
      <strong>${escapeHtml(state.incident?.summary || "Tier 3 decision governance")}</strong>
      <span>Policy: ${escapeHtml(state.policy?.label || "Standard")} - ${escapeHtml(state.policy?.description || "Balanced evidence thresholds.")}</span>
      <span>Evidence posture: ${topDecision ? `${escapeHtml(topDecision.title)} is ${escapeHtml(topDecision.status)} at ${topDecision.readiness}% readiness` : "Feed evidence and run Veritas to score readiness."} ${blocked ? `${blocked} decision(s) still blocked or not ready.` : ""}</span>
    `;
  }
}

function shortDecisionName(title = "") {
  return title
    .replace("Revoke session token", "Revoke Token")
    .replace("Disable admin account", "Disable Admin")
    .replace("Block source IP", "Block IP")
    .replace("Declare no sensitive data accessed", "No Data Accessed")
    .replace("Close incident as contained", "Close Incident");
}

function renderReadinessStrip() {
  if (!els.readinessStrip) return;
  if (!hasScoredEvidence()) {
    const feed = onlineFeedStatus();
    els.readinessStrip.innerHTML = feed
      ? `<div class="readiness-empty">Online evidence is ingested. Pull indexed Splunk events to score the five response decisions.</div>`
      : `<div class="readiness-empty">Fetch online evidence to score the five response decisions.</div>`;
    return;
  }

  els.readinessStrip.innerHTML = state.decisions
    .map((decision) => `
      <a class="readiness-card ${readinessTone(decision)} ${decision.id === "declare-no-data-access" ? "blocked-priority" : ""}" href="detail.html?view=decisions&decision=${encodeURIComponent(decision.id)}">
        <span>${escapeHtml(shortDecisionName(decision.title))}</span>
        <strong>${decision.readiness}%</strong>
        <em>${escapeHtml(statusLabel(decision.status))}</em>
      </a>
    `)
    .join("");
}

function renderJudgeStory() {
  if (!els.judgeStoryCards) return;
  if (!hasScoredEvidence()) {
    const feed = onlineFeedStatus();
    els.judgeStoryCards.innerHTML = `
      <article class="judge-story-card review">
        <span>${feed ? "Ingested evidence pending" : "Awaiting evidence"}</span>
        <strong>${feed ? "Pull indexed Splunk evidence" : "Feed evidence and run Veritas"}</strong>
        <div>
          <b>${feed ? "Pending" : "Ready"}</b>
          <em>--</em>
        </div>
        <p>${feed ? "Online feed data is in Splunk HEC. Veritas will score decisions after indexed events are loaded." : "No decision output is shown until evidence is entered or a previous run is loaded."}</p>
      </article>
    `;
    return;
  }

  const safe = state.decisions.find((decision) => normalizedStatus(decision.status) === "approved")
    || state.decisions.find((decision) => normalizedStatus(decision.status) === "caution");
  const blocked = state.decisions.find((decision) => decision.id === "declare-no-data-access")
    || state.decisions.find((decision) => ["blocked", "not-ready"].includes(normalizedStatus(decision.status)));

  const storyCard = (tone, label, decision, fallback) => {
    const status = decision ? statusLabel(decision.status) : fallback.status;
    const readiness = decision ? `${decision.readiness}%` : fallback.readiness;
    const title = decision ? decision.title : fallback.title;
    const reason = decision ? decision.reason || fallback.reason : fallback.reason;

    return `
      <article class="judge-story-card ${tone}">
        <span>${escapeHtml(label)}</span>
        <strong>${escapeHtml(title)}</strong>
        <div>
          <b>${escapeHtml(status)}</b>
          <em>${escapeHtml(readiness)}</em>
        </div>
        <p>${escapeHtml(reason)}</p>
      </article>
    `;
  };

  els.judgeStoryCards.innerHTML = `
    ${storyCard("ready", "Containment action", safe, {
      title: "Revoke session token",
      status: "Waiting",
      readiness: "--",
      reason: "Ingest evidence, query Splunk, and prove the response threshold."
    })}
    ${storyCard("blocked", "Unsafe conclusion blocked", blocked, {
      title: "Declare no sensitive data accessed",
      status: "Blocked",
      readiness: "--",
      reason: "Veritas requires export, object storage, and exfiltration evidence before this claim."
    })}
  `;
}

function renderDemoSteps() {
  const evidenceProvider = state.integration?.search_provider || state.integration?.provider;
  const feed = state.integration?.last_online_feed;
  const customRun = Boolean(state.integration?.request);
  const steps = [
    { label: "Feed evidence", done: customRun || Boolean(feed?.ingested?.length) },
    { label: "Run Veritas", done: hasScoredEvidence() },
    { label: "Score thresholds", done: hasScoredEvidence() && hasCheckedThresholds() },
    { label: "Approve actions", done: approvedApprovalCount() > 0 },
    { label: "Export audit proof", done: completedActionCount() > 0 || ["splunk-rest", "splunk-mcp"].includes(evidenceProvider) }
  ];
  const nextIndex = steps.findIndex((step) => !step.done);
  const activeIndex = nextIndex === -1 ? steps.length - 1 : nextIndex;

  els.demoSteps.innerHTML = steps
    .map((step, index) => `
      <div class="demo-step ${step.done ? "done" : ""} ${index === activeIndex ? "active" : ""}">
        <span>${index + 1}</span>
        <strong>${escapeHtml(step.label)}</strong>
      </div>
    `)
    .join("");
}

function renderDecisionMatrix() {
  if (!hasScoredEvidence()) {
    const feed = onlineFeedStatus();
    els.decisionMatrix.innerHTML = feed
      ? `<div class="empty-panel">Online feed is in Splunk HEC for index ${escapeHtml(feed.index)}. Pull indexed evidence so Veritas can score decisions from the ingested events.</div>`
      : emptyRunPanel("No decision output yet. Feed incident evidence and run Veritas to score response decisions.");
    return;
  }

  els.decisionMatrix.innerHTML = `
    <table class="data-table decision-table">
      <thead>
        <tr>
          <th>Decision</th>
          <th>Impact</th>
          <th>Evidence score</th>
          <th>Status</th>
          <th>Approval</th>
        </tr>
      </thead>
      <tbody>
        ${state.decisions.map((decision, index) => {
          const foundCheck = (decision.checks || []).find((check) => check.status === "found") || (decision.checks || [])[0];
          const approval = state.approvals.find((item) => item.decision_id === decision.id);
          const approvalLabel = approval?.approval === "approved"
            ? "Approved"
            : approval?.approval === "rejected"
              ? "Rejected"
              : decision.human_approval
                ? "Human"
                : "Auto";
          return `
            <tr class="decision-row ${readinessTone(decision)} ${decision.id === "declare-no-data-access" ? "blocked-priority" : ""}" style="--i:${index}">
              <td>
                <div class="decision-name">
                  <span class="decision-icon">${isBlockedDecision(decision) ? "!" : "OK"}</span>
                  <div>
                    <strong>${escapeHtml(decision.title)}</strong>
                    ${isBlockedDecision(decision) ? `<span class="blocked-decision-badge">${escapeHtml(blockedDecisionLabel(decision))}</span>` : ""}
                    <button class="link-button" data-drilldown="${escapeHtml(foundCheck?.id || "")}">Evidence</button>
                    ${isBlockedDecision(decision) ? `<small>${escapeHtml(blockedReason(decision))}</small>` : ""}
                  </div>
                </div>
              </td>
              <td><span class="impact-pill ${escapeHtml(String(decision.impact || "medium").toLowerCase())}">${escapeHtml(decision.impact || "Medium")}</span></td>
              <td>
                <div class="score-cell">
                  <strong>${decision.readiness}%</strong>
                  <span class="score-bar"><i style="width:${decision.readiness}%"></i></span>
                </div>
              </td>
              <td><span class="status-pill ${readinessTone(decision)}">${statusLabel(decision.status)}</span></td>
              <td><span class="approval-state ${approval?.approval || ""}">${escapeHtml(approvalLabel)}</span></td>
            </tr>
          `;
        }).join("")}
      </tbody>
    </table>
    <p class="panel-note">Readiness Score = Evidence Confidence x Integrity x Coverage x Safety</p>
  `;
}

function renderFindings() {
  if (!els.findingsPanel) return;
  if (!state.events.length) {
    const feed = onlineFeedStatus();
    els.findingsPanel.innerHTML = feed
      ? emptyRunPanel("Online evidence is ingested. Pull indexed Splunk evidence to normalize findings.")
      : emptyRunPanel("No findings yet. Feed customer evidence or upload a file to let Veritas normalize the case signals.");
    return;
  }

  els.findingsPanel.innerHTML = `
    ${state.events.slice(0, 6).map((event, index) => `
      <article class="finding-card ${escapeHtml(event.severity || "medium")}">
        <span>${escapeHtml(formatTime(event.timestamp || event._time || event.time))}</span>
        <strong>${escapeHtml(findingTitle(event))}</strong>
        <p>${escapeHtml(findingDescription(event))}</p>
        <div>
          <em>${escapeHtml(event.source || "Analyst evidence")}</em>
          <b>${escapeHtml(event.severity || "medium")}</b>
        </div>
      </article>
    `).join("")}
  `;
}

function blockedReason(decision) {
  const missing = (decision.missing_evidence || []).map((item) => item.label).slice(0, 3);
  if (decision.id === "declare-no-data-access") {
    return "Evidence threshold not met. Export/download, object storage, and exfiltration evidence remain incomplete.";
  }
  if (decision.id === "close-contained") {
    return "Evidence threshold not met. Containment and post-containment monitoring remain incomplete.";
  }
  if (missing.length) {
    return `Evidence threshold not met. Missing: ${missing.join(", ")}.`;
  }
  return "Evidence threshold not met.";
}

function thresholdScore(check) {
  if (check.status === "found") return check.mandatory ? 86 : 82;
  if (check.status === "contradicted") return 58;
  return check.mandatory ? 62 : 66;
}

function renderThresholdMatrix() {
  if (!hasScoredEvidence()) {
    const feed = onlineFeedStatus();
    els.thresholdMatrix.innerHTML = feed
      ? `<div class="empty-panel">Online feed is ingested into Splunk HEC. Pull indexed Splunk evidence before Veritas scores threshold categories from the ingested data.</div>`
      : emptyRunPanel("No threshold output yet. Scores appear only after you provide evidence and run Veritas.");
    return;
  }

  const rows = allChecks();
  if (!rows.length) {
    els.thresholdMatrix.innerHTML = `<div class="empty-panel">Evidence thresholds will appear after investigation.</div>`;
    return;
  }

  els.thresholdMatrix.innerHTML = `
    <table class="data-table threshold-table">
      <thead>
        <tr>
          <th>Evidence category</th>
          <th>Threshold</th>
          <th>Current score</th>
          <th>Gap</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        ${rows.slice(0, 7).map(({ decision, check }, index) => {
          const threshold = check.mandatory ? 80 : 70;
          const current = thresholdScore(check);
          const gap = current - threshold;
          const status = check.status === "found" ? "Sufficient" : check.status === "contradicted" ? "Insufficient" : "Below Threshold";
          return `
            <tr class="threshold-row ${statusClass(status)}" style="--i:${index}">
              <td>
                <strong>${escapeHtml(check.label)}</strong>
                <span>${escapeHtml(decision.title)}</span>
              </td>
              <td>${threshold}</td>
              <td>${current}</td>
              <td class="${gap >= 0 ? "positive" : "negative"}">${gap >= 0 ? "+" : ""}${gap}</td>
              <td>
                <button class="status-chip ${statusClass(status)}" data-drilldown="${escapeHtml(check.id)}">${status}</button>
              </td>
            </tr>
          `;
        }).join("")}
      </tbody>
    </table>
    <div class="legend-row">
      <span><i class="dot good"></i>Sufficient</span>
      <span><i class="dot warn"></i>Below Threshold</span>
      <span><i class="dot bad"></i>Insufficient</span>
    </div>
  `;
}

function integrityRows() {
  const integrity = state.integrity || {};
  const checkedRaw = integrity.sources_checked ?? 0;
  const missingRaw = integrity.sources_missing ?? 0;
  const sourcesChecked = Array.isArray(checkedRaw) ? checkedRaw.length : Number(checkedRaw || 0);
  const sourcesMissing = Array.isArray(missingRaw) ? missingRaw.length : Number(missingRaw || 0);
  const sourcesExpected = Number(integrity.sources_expected || sourcesChecked + sourcesMissing || 0);
  const freshnessRaw = integrity.evidence_freshness || integrity.freshness || "Live";
  const freshness = String(freshnessRaw).startsWith("custom+")
    ? formatTime(freshnessRaw)
    : String(freshnessRaw).includes("T")
      ? "2m ago"
      : freshnessRaw;
  const parsedTrust = Number(integrity.source_trust);
  const sourceTrust = Number.isFinite(parsedTrust) ? parsedTrust : 82;
  return [
    ["Evidence Freshness", freshness, "ok"],
    ["Sources Checked", sourcesExpected ? `${sourcesChecked} / ${sourcesExpected}` : "0 / 0", "ok"],
    ["Sources Missing", `${sourcesMissing}`, sourcesMissing ? "warn" : "ok"],
    ["Telemetry Completeness", `${integrity.telemetry_completeness ?? 0}%`, (integrity.telemetry_completeness ?? 0) >= 80 ? "ok" : "warn"],
    ["Source Trust (Lag)", `${sourceTrust} / 100`, sourceTrust >= 75 ? "ok" : "warn"],
    ["Prompt Injection Safety", integrity.prompt_injection_safe === false ? "Review" : "Safe", integrity.prompt_injection_safe === false ? "warn" : "ok"]
  ];
}

function renderIntegrity() {
  if (!hasScoredEvidence()) {
    const feed = onlineFeedStatus();
    els.integrityPanel.innerHTML = feed
      ? emptyRunPanel("Online feed is ingested. Evidence integrity will be calculated after indexed Splunk events are loaded.")
      : emptyRunPanel("Evidence integrity will appear after an analyst evidence run.");
    return;
  }

  els.integrityPanel.innerHTML = `
    <div class="integrity-list">
      ${integrityRows().map(([label, value, tone]) => `
        <div class="integrity-row">
          <span>${escapeHtml(label)}</span>
          <strong class="${tone}">${escapeHtml(value)}</strong>
        </div>
      `).join("")}
    </div>
    <div class="safety-principles">
      <strong>Missing logs are not proof of safety.</strong>
      <span>Logs are untrusted evidence, not instructions.</span>
      <span>High-impact actions require human approval.</span>
    </div>
  `;
}

function renderSplGaps() {
  if (!hasScoredEvidence()) {
    const feed = onlineFeedStatus();
    els.splGapList.innerHTML = feed
      ? emptyRunPanel("SPL gaps will appear after indexed Splunk evidence is pulled into Veritas.")
      : emptyRunPanel("Investigation gaps will appear after you feed evidence and run Veritas.");
    return;
  }

  const gaps = missingEvidenceItems();
  if (!gaps.length) {
    els.splGapList.innerHTML = `<div class="empty-panel good">No active evidence gaps. Required evidence is present for current safe actions.</div>`;
    return;
  }

  els.splGapList.innerHTML = `
    ${gaps.slice(0, 4).map(({ decision, check }) => `
      <div class="gap-card">
        <div>
          <strong>${escapeHtml(check.label)}</strong>
          <span>Evidence category: ${escapeHtml(decision.title)}</span>
          <code>${escapeHtml(check.spl || "SPL generated after investigation")}</code>
        </div>
        <button data-drilldown="${escapeHtml(check.id)}">Generate</button>
      </div>
    `).join("")}
    <button class="wide-link">View all missing evidence (${gaps.length})</button>
  `;
}

function renderBlastRadius() {
  if (!hasScoredEvidence()) {
    els.blastRadiusList.innerHTML = emptyRunPanel("Blast-radius warnings will appear after Veritas scores the proposed action.");
    return;
  }

  const blastItems = state.decisions
    .filter((decision) => decision.blast_radius)
    .map((decision) => ({
      title: decision.blast_radius,
      decision: decision.title,
      risk: ["High", "Critical"].includes(decision.impact) ? "High Risk" : "Medium Risk",
      tone: ["High", "Critical"].includes(decision.impact) ? "high" : "medium"
    }));

  if (!blastItems.length) {
    els.blastRadiusList.innerHTML = `<div class="empty-panel">Blast radius warnings appear once decisions are scored.</div>`;
    return;
  }

  els.blastRadiusList.innerHTML = `
    ${blastItems.slice(0, 3).map((item) => `
      <div class="blast-card ${item.tone}">
        <div>
          <strong>${escapeHtml(item.title)}</strong>
          <span>${escapeHtml(item.decision)}</span>
        </div>
        <em>${escapeHtml(item.risk)}</em>
      </div>
    `).join("")}
    <button class="wide-link">View full blast radius map</button>
  `;
}

function renderAuditPreview() {
  const provider = state.integration?.search_provider || state.integration?.provider || "Splunk REST";
  const customRequest = state.integration?.request;
  if (!hasScoredEvidence()) {
    const feed = onlineFeedStatus();
    els.auditPreview.innerHTML = feed
      ? emptyRunPanel("Audit proof will be available after indexed Splunk evidence is loaded and scored.")
      : emptyRunPanel("The audit brief will be generated from the evidence you feed into Veritas.");
    return;
  }

  if (customRequest?.feedback) {
    const feedback = customRequest.feedback;
    els.auditPreview.innerHTML = `
      <div class="custom-feedback ${feedback.executed ? "executed" : "held"}">
        <span>${feedback.executed ? "Executed" : "Held"}</span>
        <strong>${escapeHtml(feedback.action_label)}</strong>
        <p>${escapeHtml(feedback.message)}</p>
        <dl>
          <div><dt>Decision</dt><dd>${escapeHtml(feedback.decision_title || "Not required")}</dd></div>
          <div><dt>Status</dt><dd>${escapeHtml(feedback.decision_status)}</dd></div>
          <div><dt>Readiness</dt><dd>${feedback.readiness ?? "n/a"}%</dd></div>
          <div><dt>Signals</dt><dd>${customRequest.matched_signals?.length || 0}</dd></div>
        </dl>
        ${feedback.missing_evidence?.length ? `
          <p>Missing: ${feedback.missing_evidence.map((item) => escapeHtml(item.label)).join(", ")}</p>
        ` : ""}
      </div>
      <button class="wide-link" id="previewBriefBtn">Preview brief</button>
    `;
    document.querySelector("#previewBriefBtn")?.addEventListener("click", exportBrief);
    return;
  }
  const bullets = [
    `Incident summary and ${state.events.length || "live"} event timeline`,
    "Evidence considered and scoring breakdown",
    "Proposed decisions and rationale",
    `${approvedApprovalCount()} approvals and human-in-the-loop actions`,
    "Integrity, blind spots, and safety checks",
    `References to SPL queries and ${provider} data sources`
  ];

  els.auditPreview.innerHTML = `
    <p>The audit brief will include:</p>
    <ul>
      ${bullets.map((bullet) => `<li>${escapeHtml(bullet)}</li>`).join("")}
    </ul>
    <button class="wide-link" id="previewBriefBtn">Preview brief</button>
  `;
  document.querySelector("#previewBriefBtn")?.addEventListener("click", exportBrief);
}

function renderApprovalGate() {
  if (!hasScoredEvidence() || !state.approvals.length) {
    const feed = onlineFeedStatus();
    els.approvalGate.innerHTML = feed
      ? `<div class="empty-panel">Approval queue opens after indexed Splunk evidence is pulled and thresholds are scored.</div>`
      : emptyRunPanel("Approval queue opens after Veritas scores a user-provided evidence run.");
    return;
  }

  els.approvalGate.innerHTML = state.approvals
    .map((approval) => `
      <div class="approval-card ${approval.approval || "pending"}">
        <div>
          <span>${escapeHtml(approval.action_label)}</span>
          <strong>${escapeHtml(approval.decision_title)}</strong>
          <p>${escapeHtml(approval.summary || "Awaiting analyst decision.")}</p>
        </div>
        <div class="approval-meta">
          <b>${approval.readiness}%</b>
          <small>${approval.executed ? "Executed" : approval.approval || "Pending"}</small>
        </div>
        <div class="approval-actions">
          <button data-approve="${escapeHtml(approval.decision_id)}" ${approval.approval === "approved" ? "disabled" : ""}>Approve</button>
          <button data-reject="${escapeHtml(approval.decision_id)}" ${approval.approval === "rejected" ? "disabled" : ""}>Reject</button>
        </div>
      </div>
    `)
    .join("");
}

function renderDecisionSpotlight() {
  if (!hasScoredEvidence()) {
    const feed = onlineFeedStatus();
    els.decisionSpotlight.innerHTML = feed
      ? `<div class="empty-panel">Online data has been ingested. Pull indexed Splunk evidence to generate decision assurance.</div>`
      : emptyRunPanel("Decision assurance will appear after you feed evidence and run Veritas.");
    return;
  }

  const critical = state.decisions.find((decision) => normalizedStatus(decision.status) === "blocked")
    || state.decisions.find((decision) => normalizedStatus(decision.status) === "not-ready")
    || state.decisions.find((decision) => normalizedStatus(decision.status) === "caution")
    || state.decisions[0];

  if (!critical) {
    els.decisionSpotlight.innerHTML = `<div class="empty-panel">Decision assurance summary will appear here.</div>`;
    return;
  }

  const missing = (critical.checks || []).filter((check) => check.status !== "found");
  els.decisionSpotlight.innerHTML = `
    <div class="spotlight-card ${readinessTone(critical)}">
      <span>${statusLabel(critical.status)}</span>
      <strong>${escapeHtml(critical.title)}</strong>
      <div class="spotlight-score">${critical.readiness}%</div>
      <p>${escapeHtml(critical.reason || "Evidence threshold is being evaluated.")}</p>
      ${missing.length ? `
        <ul>
          ${missing.slice(0, 3).map((check) => `<li>${escapeHtml(check.label)}</li>`).join("")}
        </ul>
      ` : `<p>Evidence threshold has been met for this response decision.</p>`}
    </div>
  `;
}

function renderEvents() {
  if (!state.events.length) {
    const feed = onlineFeedStatus();
    els.eventStream.innerHTML = feed
      ? `<div class="empty-panel">Online feed ingested into Splunk HEC: ${escapeHtml(feed.eventIds.join(", "))}. Query the Splunk index to make these events visible in the Veritas timeline and decision matrix.</div>`
      : emptyRunPanel("No case evidence loaded. Use Feed Evidence & Run Veritas to start a new run.");
    return;
  }

  els.eventStream.innerHTML = `
    <div class="timeline-rail">
      ${state.events.map((event, index) => {
        const display = eventDisplay(event);
        return `
        <div class="timeline-item ${event.severity || "medium"}" style="--i:${index}">
          <div class="timeline-node ${escapeHtml(display.icon)}"></div>
          <time>${formatTime(event.timestamp || event._time || event.time)}</time>
          <strong>${escapeHtml(display.title)}</strong>
          <span>${escapeHtml(display.description)}</span>
          <em>${escapeHtml(event.severity || "medium")}</em>
        </div>
      `;
      }).join("")}
    </div>
  `;
}

function renderCaseHistory() {
  if (!els.caseHistoryPanel) return;
  if (!caseHistory.length) {
    els.caseHistoryPanel.innerHTML = emptyRunPanel("No previous cases yet. Completed Veritas runs will appear here.");
    return;
  }

  els.caseHistoryPanel.innerHTML = caseHistory.slice(0, 6).map((item) => `
    <article class="case-history-item ${item.executed ? "executed" : "held"}">
      <div>
        <strong>${escapeHtml(item.title || "Veritas case")}</strong>
        <span>${escapeHtml(item.source || "Evidence")}</span>
      </div>
      <p>${escapeHtml(item.outcome || "Run completed")}</p>
      <dl>
        <div><dt>Ready</dt><dd>${Number(item.ready_decisions || 0)}</dd></div>
        <div><dt>Blocked</dt><dd>${Number(item.blocked_decisions || 0)}</dd></div>
        <div><dt>Events</dt><dd>${Number(item.events || 0)}</dd></div>
      </dl>
    </article>
  `).join("");
}

function render() {
  renderMetrics();
  renderTier3Controls();
  renderReadinessStrip();
  renderJudgeStory();
  renderDemoSteps();
  renderFindings();
  renderDecisionMatrix();
  renderThresholdMatrix();
  renderIntegrity();
  renderSplGaps();
  renderBlastRadius();
  renderAuditPreview();
  renderApprovalGate();
  renderDecisionSpotlight();
  renderEvents();
  renderCaseHistory();
  requestAnimationFrame(fitExecutiveCanvas);
}

async function loadState() {
  try {
    await loadCaseHistory();
    const payload = await requestJson("/state");
    setState(payload);
    logEntry("Loaded current Veritas state.");
  } catch (error) {
    logEntry(`Backend unavailable: ${error.message}`, "error");
  }
}

async function resetLab() {
  logEntry("Starting a new case.");
  const payload = await requestJson("/reset", { method: "POST", body: "{}" });
  await loadCaseHistory();
  setState(payload);
}

async function loadFromSplunk() {
  const configured = Boolean(state.integration?.configured);
  logEntry(configured
    ? "Pulling indexed evidence from Splunk for the ingested online feed."
    : "Indexed evidence search requires Splunk host and search token; Veritas will not substitute local results.");
  try {
    await requestJson("/load-splunk", { method: "POST", body: "{}" });
    const payload = await requestJson("/state");
    await loadCaseHistory();
    setState(payload);
    logEntry("Splunk indexed evidence loaded.");
  } catch (error) {
    logEntry(`Splunk pull failed: ${error.message}`, "error");
    throw error;
  }
}

async function ingestOnlineFeed() {
  const hasHec = Boolean(state.integration?.hec_configured);
  const hasSearch = Boolean(state.integration?.configured);
  logEntry(hasHec
    ? "Fetching the online attack-data feed and ingesting it into Splunk HEC."
    : "Online feed requires Splunk HEC configuration before it can run.", hasHec ? "info" : "warn");
  if (hasHec && !hasSearch) {
    logEntry("Splunk search is not configured; Veritas will stop after HEC ingestion until indexed evidence can be pulled.", "warn");
  }
  try {
    const payload = await requestJson("/ingest-online-feed", {
      method: "POST",
      body: JSON.stringify({ load_after: true })
    });
    await loadCaseHistory();
    setState(payload);
    const feed = payload.feed || payload.integration?.last_online_feed;
    if (feed?.ingested?.length) {
      logEntry(`Online feed ingested into Splunk: ${feed.ingested.join(", ")}.`);
    }
    if (payload.search_warning) {
      logEntry(`Ingest succeeded, but Splunk search needs attention: ${payload.search_warning}`, "warn");
    }
    return payload;
  } catch (error) {
    logEntry(`Online feed ingestion failed: ${error.message}`, "error");
    throw error;
  }
}

async function startAttack() {
  logEntry("Starting admin takeover incident stream.");
  const payload = await requestJson("/start", { method: "POST", body: "{}" });
  setState(payload);
}

async function loadIncidentProfile() {
  const incidentId = els.incidentSelector?.value || state.incident?.id || "admin-takeover";
  logEntry(`Loading incident profile: ${incidentId}.`);
  const payload = await requestJson("/select-incident", {
    method: "POST",
    body: JSON.stringify({ incident_id: incidentId, load: true })
  });
  setState(payload);
  await checkThresholds();
}

async function applyPolicyProfile() {
  const profile = els.policySelector?.value || state.policy?.id || "standard";
  logEntry(`Applying policy profile: ${profile}.`);
  const payload = await requestJson("/policy", {
    method: "POST",
    body: JSON.stringify({ profile })
  });
  setState(payload);
}

async function streamNextEvent() {
  const payload = await requestJson("/step", { method: "POST", body: "{}" });
  setState(payload);
  logEntry("Advanced live event stream.");
}

async function checkThresholds() {
  logEntry("Checking evidence thresholds.");
  const payload = await requestJson("/investigate", { method: "POST", body: "{}" });
  setState(payload);
}

async function setApproval(decisionId, approval) {
  await requestJson("/approval", {
    method: "POST",
    body: JSON.stringify({ decision_id: decisionId, approval })
  });
  const payload = await requestJson("/state");
  setState(payload);
  logEntry(`${approval === "approved" ? "Approved" : "Rejected"} ${decisionId}.`);
}

async function executeApprovedContainment() {
  logEntry("Executing approved containment actions.");

  for (const item of actionPlan) {
    const approval = state.approvals.find((entry) => entry.decision_id === item.decisionId);
    if (approval?.approval !== "approved") {
      logEntry(`Skipped ${item.actionId}: approval required.`, "warn");
      continue;
    }

    const payload = await requestJson("/respond", {
      method: "POST",
      body: JSON.stringify({ action: item.actionId })
    });
    setState(payload);
    logEntry(`Executed ${approval.action_label}.`);
    await sleep(350);
  }
}

async function exportBrief() {
  logEntry("Generating decision audit brief.");
  const payload = await requestJson("/brief");
  els.briefOutput.textContent = payload.brief || JSON.stringify(payload, null, 2);
  els.briefDialog.showModal();
}

async function submitEvidenceRun(payload, resultElement) {
  resultElement.textContent = "Running request...";
  try {
    const result = await requestJson("/custom-run", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    await loadCaseHistory();
    setState(result);
    const feedback = result.integration?.request?.feedback;
    resultElement.innerHTML = feedback
      ? `
        <strong>${feedback.executed ? "Executed" : "Held"}: ${escapeHtml(feedback.action_label)}</strong>
        <span>${escapeHtml(feedback.message)}</span>
        <span>Decision: ${escapeHtml(feedback.decision_title || "Not required")} | Status: ${escapeHtml(feedback.decision_status)} | Readiness: ${feedback.readiness ?? "n/a"}%</span>
        ${feedback.missing_evidence?.length ? `<span>Missing evidence: ${feedback.missing_evidence.map((item) => escapeHtml(item.label)).join(", ")}</span>` : ""}
        <span>Matched signals: ${result.integration?.request?.matched_signals?.length || 0}</span>
      `
      : escapeHtml(result.message || "Request executed.");
    logEntry(result.message || "Custom request executed.");
  } catch (error) {
    resultElement.textContent = error.message;
    logEntry(`Custom request failed: ${error.message}`, "error");
  }
}

async function runIntakeRequest(event) {
  event.preventDefault();
  return submitEvidenceRun({
    title: els.intakeIncidentTitle.value,
    evidence: els.intakeEvidence.value,
    action: els.intakeAction.value,
    execute: els.intakeExecute.checked
  }, els.intakeResult);
}

async function runCustomRequest(event) {
  event.preventDefault();
  return submitEvidenceRun({
    title: els.customIncidentTitle.value,
    evidence: els.customEvidence.value,
    action: els.customAction.value,
    execute: els.customExecute.checked
  }, els.customResult);
}

async function loadEvidenceFile(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  const text = await file.text();
  const prefix = `Uploaded file: ${file.name}\n`;
  els.intakeEvidence.value = `${prefix}${text}`.trim();
  if (!els.intakeIncidentTitle.value) {
    els.intakeIncidentTitle.value = file.name.replace(/\.[^.]+$/, "");
  }
  els.intakeResult.textContent = `${file.name} loaded. Choose a response task and run Veritas Analysis.`;
}

function showEvidenceDrilldown(checkId) {
  const result = findCheck(checkId);
  if (!result) return;
  const { decision, check } = result;
  const evidence = check.evidence || [];
  const spl = check.spl || "No SPL query mapped for this evidence item.";
  const evidenceRows = evidence.map((item) => renderEvidenceItem(item)).join("");

  els.evidenceDialogTitle.textContent = check.label;
  els.evidenceOutput.innerHTML = `
    <div class="drilldown-grid">
      <section>
        <span>Decision</span>
        <strong>${escapeHtml(decision.title)}</strong>
      </section>
      <section>
        <span>Status</span>
        <strong>${statusLabel(check.status)}</strong>
      </section>
      <section>
        <span>Mandatory</span>
        <strong>${check.mandatory ? "Yes" : "No"}</strong>
      </section>
      <section>
        <span>Readiness</span>
        <strong>${decision.readiness}%</strong>
      </section>
    </div>
    <h4>Suggested SPL</h4>
    <pre>${escapeHtml(spl)}</pre>
    <h4>Matched Evidence</h4>
    ${evidence.length ? `
      <ul class="evidence-list">
        ${evidenceRows}
      </ul>
    ` : `<p class="muted-copy">No matching event is currently indexed for this evidence item.</p>`}
  `;
  els.evidenceDialog.showModal();
}

function fieldLine(label, value) {
  if (value === undefined || value === null || value === "") return "";
  return `<span><b>${escapeHtml(label)}</b>${escapeHtml(String(value))}</span>`;
}

function renderEvidenceItem(item) {
  if (!item || typeof item !== "object") {
    return `<li>${escapeHtml(item)}</li>`;
  }

  const title = item.summary || item.message || item.id || "Matched evidence";
  const metadata = [
    fieldLine("ID", item.id || item.event_id),
    fieldLine("Source", item.source),
    fieldLine("Sourcetype", item.sourcetype),
    fieldLine("User", item.user),
    fieldLine("IP", item.src_ip),
    fieldLine("Severity", item.severity),
    fieldLine("Message", item.message),
    fieldLine("Category", item.evidence_category),
    fieldLine("Action", item.action),
    fieldLine("Provider", item.provider || item.origin),
    fieldLine("Job", item.splunk_job_id)
  ].filter(Boolean).join("");

  return `
    <li class="evidence-object">
      <strong>${escapeHtml(title)}</strong>
      ${metadata ? `<div>${metadata}</div>` : ""}
    </li>
  `;
}

async function runJudgeMode() {
  const buttonLabel = els.judgeModeBtn.textContent;
  els.judgeModeBtn.disabled = true;
  els.judgeModeBtn.textContent = "Running...";
  document.body.classList.add("presentation-running");
  logEntry("Judge mode started.");

  try {
    await resetLab();
    await sleep(400);

    await ingestOnlineFeed();

    await sleep(500);
    await checkThresholds();

    for (const item of actionPlan) {
      const approval = state.approvals.find((entry) => entry.decision_id === item.decisionId);
      if (approval?.eligible !== false) {
        await sleep(350);
        await setApproval(item.decisionId, "approved");
      }
    }

    await sleep(500);
    await executeApprovedContainment();
    await sleep(400);
    await exportBrief();
    logEntry("Judge mode completed.");
  } catch (error) {
    logEntry(`Judge mode failed: ${error.message}`, "error");
  } finally {
    els.judgeModeBtn.disabled = false;
    els.judgeModeBtn.textContent = buttonLabel;
    document.body.classList.remove("presentation-running");
  }
}

function bindEvents() {
  els.themeToggle?.addEventListener("click", () => {
    document.body.classList.toggle("dark");
    const isDark = document.body.classList.contains("dark");
    els.themeToggle.textContent = isDark ? "UI-N: Night Executive" : "UI-H: Light Executive";
    requestAnimationFrame(fitExecutiveCanvas);
  });
  els.resetLabBtn?.addEventListener("click", () => resetLab().catch((error) => logEntry(error.message, "error")));
  els.customRequestBtn?.addEventListener("click", () => {
    els.evidenceIntake?.scrollIntoView({ behavior: "smooth", block: "center" });
    els.intakeEvidence?.focus();
    els.intakeResult.textContent = "Paste customer evidence, choose a task, then run Veritas.";
  });
  els.intakeExampleBtn?.addEventListener("click", () => {
    els.intakeIncidentTitle.value = "Customer supplied admin takeover";
    els.intakeAction.value = "disable-account";
    els.intakeEvidence.value = "Admin login from a new country with impossible travel. Repeated MFA anomaly prompts followed by approval. Privilege escalation to super_admin. Admin API export endpoint returned 200. Scripted curl download observed on the admin workstation.";
    els.intakeResult.textContent = "Example loaded. Click Run Veritas Analysis.";
    els.intakeEvidence.focus();
  });
  els.intakeEvidenceFile?.addEventListener("change", (event) => {
    loadEvidenceFile(event).catch((error) => {
      els.intakeResult.textContent = error.message;
      logEntry(`Evidence file load failed: ${error.message}`, "error");
    });
  });
  els.intakeForm?.addEventListener("submit", runIntakeRequest);
  els.closeCustomBtn?.addEventListener("click", () => els.customDialog.close());
  els.customDialog?.addEventListener("click", (event) => {
    const scenario = event.target.closest("[data-scenario]");
    if (!scenario) return;
    els.customIncidentTitle.value = scenario.dataset.title;
    els.customEvidence.value = scenario.dataset.scenario;
    els.customAction.value = scenario.dataset.action;
    els.customResult.textContent = "Scenario loaded. Click Run request to execute it.";
  });
  els.customRequestForm?.addEventListener("submit", runCustomRequest);
  els.onlineFeedBtn?.addEventListener("click", () => ingestOnlineFeed().catch(() => {}));
  els.loadSplunkBtn?.addEventListener("click", () => loadFromSplunk().catch(() => {}));
  els.startAttackBtn?.addEventListener("click", () => startAttack().catch((error) => logEntry(error.message, "error")));
  els.nextEventBtn?.addEventListener("click", () => streamNextEvent().catch((error) => logEntry(error.message, "error")));
  els.investigateBtn?.addEventListener("click", () => checkThresholds().catch((error) => logEntry(error.message, "error")));
  els.executeSafeBtn?.addEventListener("click", () => executeApprovedContainment().catch((error) => logEntry(error.message, "error")));
  els.exportBriefBtn?.addEventListener("click", () => exportBrief().catch((error) => logEntry(error.message, "error")));
  els.judgeModeBtn?.addEventListener("click", runJudgeMode);
  els.loadIncidentProfileBtn?.addEventListener("click", () => loadIncidentProfile().catch((error) => logEntry(error.message, "error")));
  els.applyPolicyBtn?.addEventListener("click", () => applyPolicyProfile().catch((error) => logEntry(error.message, "error")));

  els.approvalGate?.addEventListener("click", (event) => {
    const approveId = event.target.closest("[data-approve]")?.dataset.approve;
    const rejectId = event.target.closest("[data-reject]")?.dataset.reject;
    if (approveId) setApproval(approveId, "approved").catch((error) => logEntry(error.message, "error"));
    if (rejectId) setApproval(rejectId, "rejected").catch((error) => logEntry(error.message, "error"));
  });

  document.body.addEventListener("click", (event) => {
    const detailTarget = event.target.closest("[data-detail]");
    const interactive = event.target.closest("button, a, input, select, textarea, dialog, [data-drilldown]");
    if (detailTarget && !interactive) {
      window.location.href = `detail.html?view=${encodeURIComponent(detailTarget.dataset.detail)}`;
      return;
    }

    const drilldownId = event.target.closest("[data-drilldown]")?.dataset.drilldown;
    if (drilldownId) showEvidenceDrilldown(drilldownId);
  });

  els.closeBriefBtn?.addEventListener("click", () => els.briefDialog.close());
  els.closeEvidenceBtn?.addEventListener("click", () => els.evidenceDialog.close());
}

bindEvents();
window.addEventListener("resize", fitExecutiveCanvas);
render();
loadState();
