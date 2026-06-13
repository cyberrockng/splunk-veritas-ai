const API_ORIGIN = (
  window.VERITAS_API_ORIGIN
  || new URLSearchParams(window.location.search).get("api")
  || ""
).replace(/\/$/, "");
const API_BASE = `${API_ORIGIN}/api/sentinel`;

const params = new URLSearchParams(window.location.search);
const view = params.get("view") || "risk";
const decisionFilter = params.get("decision");

const titles = {
  incident: ["Incident Overview", "Current incident state, evidence source, and action readiness."],
  risk: ["Residual Risk Score", "Risk movement, decision readiness, and containment effect."],
  decisions: ["Response Decision Queue", "Approve, hold, or inspect response decisions with evidence."],
  matrix: ["Evidence Threshold Matrix", "Every evidence requirement, status, SPL query, and matched evidence."],
  integrity: ["Evidence Integrity & Blind Spots", "Evidence quality, source coverage, and missing telemetry."],
  missing: ["Investigation Gaps to SPL", "Run the right Splunk searches to close evidence gaps."],
  blast: ["Blast Radius & Decision Risk", "What could go wrong before an action is approved."],
  audit: ["Tier 3 Decision Audit Brief", "Exportable governance record and custom request result."],
  timeline: ["Attack Path Timeline", "Chronological evidence from Splunk or custom input."],
};

const actionMap = {
  "revoke-session": "revoke-token",
  "disable-admin": "disable-account",
  "block-source-ip": "block-ip",
};

const els = {
  eyebrow: document.querySelector("#detailEyebrow"),
  title: document.querySelector("#detailTitle"),
  subtitle: document.querySelector("#detailSubtitle"),
  risk: document.querySelector("#detailRisk"),
  provider: document.querySelector("#detailProvider"),
  mode: document.querySelector("#detailMode"),
  events: document.querySelector("#detailEvents"),
  stage: document.querySelector("#detailStage"),
  content: document.querySelector("#detailContent"),
  refreshBtn: document.querySelector("#refreshBtn"),
  runCustomBtn: document.querySelector("#runCustomBtn"),
  exportBriefBtn: document.querySelector("#exportBriefBtn"),
  form: document.querySelector("#detailCustomForm"),
  customTitle: document.querySelector("#detailCustomTitle"),
  customAction: document.querySelector("#detailCustomAction"),
  customEvidence: document.querySelector("#detailCustomEvidence"),
  customExecute: document.querySelector("#detailCustomExecute"),
  customResult: document.querySelector("#detailCustomResult"),
  briefDialog: document.querySelector("#detailBriefDialog"),
  briefOutput: document.querySelector("#detailBriefOutput"),
  closeBriefBtn: document.querySelector("#closeBriefBtn"),
};

let state = null;

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

function providerInfo(integration = {}) {
  const provider = integration.search_provider || integration.provider || "mock-mcp";

  if (provider === "splunk-rest") {
    return {
      provider,
      source: "Splunk REST",
      mode: "Real indexed evidence",
      tone: "real"
    };
  }

  if (provider === "splunk-mcp") {
    return {
      provider,
      source: "Splunk MCP",
      mode: "MCP-routed indexed evidence",
      tone: "real"
    };
  }

  if (provider === "mock-mcp-fallback") {
    return {
      provider,
      source: "mock-mcp fallback",
      mode: "Splunk unavailable; safe fallback active",
      tone: "fallback"
    };
  }

  if (provider === "custom-input") {
    return {
      provider,
      source: "custom analyst input",
      mode: "Analyst-supplied evidence evaluation",
      tone: "mock"
    };
  }

  return {
    provider: "mock-mcp",
    source: "mock-mcp",
    mode: "Safe deterministic demo",
    tone: "mock"
  };
}

async function requestJson(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
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

function setHeader() {
  const [title, subtitle] = titles[view] || titles.risk;
  const provider = providerInfo(state?.integration);
  els.eyebrow.textContent = `Tier 3 Decision Detail / ${provider.source}`;
  els.title.textContent = title;
  els.subtitle.textContent = subtitle;
  els.risk.textContent = state?.risk ?? "--";
  els.provider.textContent = provider.provider;
  els.mode.textContent = provider.mode;
  els.mode.className = `detail-mode-label mode-${provider.tone}`;
  els.events.textContent = state?.events?.length ?? "--";
  els.stage.textContent = state?.stage ?? "--";
}

function readinessTone(decision) {
  const status = statusClass(decision.status);
  if (status === "approved") return "ready";
  if (status === "blocked" || status === "not-ready") return "blocked";
  if (status === "caution") return "caution";
  return "review";
}

function isBlockedDecision(decision) {
  return readinessTone(decision) === "blocked";
}

function blockedDecisionLabel(decision) {
  if (!isBlockedDecision(decision)) return "";
  return decision.id === "declare-no-data-access"
    ? "Unsafe conclusion blocked"
    : "Evidence gate blocked";
}

function allChecks() {
  return (state.decisions || []).flatMap((decision) =>
    (decision.checks || []).map((check) => ({ decision, check })),
  );
}

function missingChecks() {
  return allChecks().filter(({ check }) => check.status !== "found");
}

function detailField(label, value) {
  if (value === undefined || value === null || value === "") return "";
  return `<span><b>${escapeHtml(label)}</b>${escapeHtml(String(value))}</span>`;
}

function renderDetailEvidenceItem(item) {
  if (!item || typeof item !== "object") {
    return `<li>${escapeHtml(item)}</li>`;
  }

  const title = item.summary || item.message || item.id || item.event_id || "Evidence item";
  const fields = [
    detailField("ID", item.id || item.event_id),
    detailField("Source", item.source),
    detailField("Sourcetype", item.sourcetype),
    detailField("User", item.user),
    detailField("IP", item.src_ip),
    detailField("Severity", item.severity),
    detailField("Message", item.message),
    detailField("Category", item.evidence_category),
    detailField("Action", item.action),
    detailField("Provider", item.provider || item.origin),
    detailField("Job", item.splunk_job_id),
  ].filter(Boolean).join("");

  return `
    <li class="detail-evidence-item">
      <strong>${escapeHtml(title)}</strong>
      ${fields ? `<div>${fields}</div>` : ""}
    </li>
  `;
}

function renderEvidenceDrilldown(check) {
  const evidence = check.evidence || [];
  if (!evidence.length) {
    return `<p class="detail-empty-evidence">No matching event is currently indexed for this evidence item.</p>`;
  }

  return `
    <ul class="detail-evidence-list">
      ${evidence.map((item) => renderDetailEvidenceItem(item)).join("")}
    </ul>
  `;
}

function renderDecisionCards() {
  return `
    <div class="detail-card-grid">
      ${state.decisions.map((decision) => {
        const actionId = actionMap[decision.id];
        const approval = state.approvals.find((item) => item.decision_id === decision.id);
        return `
          <article class="detail-card ${readinessTone(decision)} ${decision.id === "declare-no-data-access" ? "blocked-priority" : ""}">
            <span>${escapeHtml(decision.impact)} impact</span>
            <h3>${escapeHtml(decision.title)}</h3>
            ${isBlockedDecision(decision) ? `<strong class="detail-blocked-banner">${escapeHtml(blockedDecisionLabel(decision))}</strong>` : ""}
            <div class="detail-score">${decision.readiness}%</div>
            <p>${escapeHtml(decision.reason)}</p>
            <div class="detail-chip-row">
              <span>${escapeHtml(decision.status)}</span>
              <span>Approval: ${escapeHtml(approval?.approval || "pending")}</span>
            </div>
            <ul>
              ${decision.checks.map((check) => `<li>${escapeHtml(check.label)}: ${escapeHtml(check.status)}</li>`).join("")}
            </ul>
            <div class="detail-action-row">
              ${approval?.eligible ? `<button data-approve="${escapeHtml(decision.id)}">Approve</button>` : ""}
              ${approval?.approval === "approved" && actionId ? `<button data-execute="${escapeHtml(actionId)}">Execute</button>` : ""}
              <button data-view-checks="${escapeHtml(decision.id)}">Show evidence</button>
            </div>
          </article>
        `;
      }).join("")}
    </div>
  `;
}

function renderMatrix() {
  const rows = decisionFilter
    ? allChecks().filter(({ decision }) => decision.id === decisionFilter)
    : allChecks();
  return `
    <table class="detail-table">
      <thead>
        <tr>
          <th>Decision</th>
          <th>Evidence</th>
          <th>Status</th>
          <th>Mandatory</th>
          <th>SPL / Evidence</th>
        </tr>
      </thead>
      <tbody>
        ${rows.map(({ decision, check }) => `
          <tr class="detail-matrix-row ${readinessTone(decision)} ${decision.id === "declare-no-data-access" ? "blocked-priority" : ""}">
            <td data-label="Decision">${escapeHtml(decision.title)}</td>
            <td data-label="Evidence">${escapeHtml(check.label)}</td>
            <td data-label="Status"><span class="detail-status ${statusClass(check.status)}">${escapeHtml(check.status)}</span></td>
            <td data-label="Mandatory">${check.mandatory ? "Yes" : "No"}</td>
            <td data-label="SPL / Evidence">
              <code>${escapeHtml(check.spl)}</code>
              ${renderEvidenceDrilldown(check)}
            </td>
          </tr>
        `).join("") || `<tr><td colspan="5">No evidence checks matched this filter.</td></tr>`}
      </tbody>
    </table>
  `;
}

function renderIntegrity() {
  const integrity = state.integrity || {};
  const checked = Array.isArray(integrity.sources_checked) ? integrity.sources_checked : [];
  const missing = Array.isArray(integrity.sources_missing) ? integrity.sources_missing : [];
  return `
    <div class="detail-card-grid">
      <article class="detail-card">
        <span>Telemetry completeness</span>
        <div class="detail-score">${integrity.telemetry_completeness || 0}%</div>
        <p>Missing telemetry lowers readiness. Missing logs are not treated as proof of safety.</p>
      </article>
      <article class="detail-card">
        <span>Sources checked</span>
        <h3>${checked.length || 0} sources</h3>
        <ul>${checked.map((item) => `<li>${escapeHtml(item)}</li>`).join("") || "<li>No source checked yet.</li>"}</ul>
      </article>
      <article class="detail-card blocked">
        <span>Sources missing</span>
        <h3>${missing.length || 0} gaps</h3>
        <ul>${missing.map((item) => `<li>${escapeHtml(item)}</li>`).join("") || "<li>No missing sources.</li>"}</ul>
      </article>
    </div>
  `;
}

function renderMissing() {
  const gaps = missingChecks();
  return `
    <div class="detail-card-grid">
      ${gaps.map(({ decision, check }) => `
        <article class="detail-card blocked">
          <span>${escapeHtml(decision.title)}</span>
          <h3>${escapeHtml(check.label)}</h3>
          <p>Status: ${escapeHtml(check.status)}. Mandatory: ${check.mandatory ? "yes" : "no"}.</p>
          <code>${escapeHtml(check.spl)}</code>
        </article>
      `).join("") || `<article class="detail-card ready"><h3>No missing evidence</h3><p>All current evidence thresholds are satisfied.</p></article>`}
    </div>
  `;
}

function renderBlast() {
  return `
    <div class="detail-card-grid">
      ${state.decisions.map((decision) => `
        <article class="detail-card ${readinessTone(decision)}">
          <span>${escapeHtml(decision.impact)} impact</span>
          <h3>${escapeHtml(decision.title)}</h3>
          <p>${escapeHtml(decision.blast_radius)}</p>
          <strong>${escapeHtml(decision.recommended_action)}</strong>
        </article>
      `).join("")}
    </div>
  `;
}

function renderAudit() {
  const request = state.integration?.request;
  return `
    ${request?.feedback ? `
      <article class="detail-card ${request.feedback.executed ? "ready" : "caution"}">
        <span>${request.feedback.executed ? "Executed" : "Held"}</span>
        <h3>${escapeHtml(request.feedback.action_label)}</h3>
        <p>${escapeHtml(request.feedback.message)}</p>
        <p>Readiness: ${request.feedback.readiness ?? "n/a"}%. Matched signals: ${request.matched_signals?.length || 0}.</p>
        ${request.feedback.missing_evidence?.length ? `<ul>${request.feedback.missing_evidence.map((item) => `<li>${escapeHtml(item.label)}</li>`).join("")}</ul>` : ""}
      </article>
    ` : ""}
    <article class="detail-card">
      <h3>Audit brief is ready to export</h3>
      <p>The brief includes evidence timeline, readiness decisions, missing SPL, approvals, and containment actions.</p>
      <button data-export-brief>Open full brief</button>
    </article>
  `;
}

function renderTimeline() {
  return `
    <div class="detail-timeline">
      ${(state.events || []).map((event) => `
        <article class="detail-card">
          <span>${escapeHtml(event.time || event._time || "event")}</span>
          <h3>${escapeHtml(event.id || event.event_id || "Security event")}</h3>
          <p>${escapeHtml(event.summary || event.description || event.message || "")}</p>
          <div class="detail-chip-row">
            <span>${escapeHtml(event.source || "source unknown")}</span>
            <span>${escapeHtml(event.severity || "medium")}</span>
          </div>
        </article>
      `).join("") || `<article class="detail-card"><h3>No events loaded</h3><p>Run a custom request or pull Splunk evidence.</p></article>`}
    </div>
  `;
}

function renderRisk() {
  const ready = state.decisions.filter((item) => ["Approved", "Caution"].includes(item.status)).length;
  const blocked = state.decisions.filter((item) => ["Blocked", "Not Ready"].includes(item.status)).length;
  return `
    <div class="detail-card-grid">
      <article class="detail-card">
        <span>Current risk</span>
        <div class="detail-score">${state.risk}/100</div>
        <p>${state.risk >= 75 ? "High response risk." : state.risk >= 45 ? "Elevated response risk." : "Controlled but still evidence-bound."}</p>
      </article>
      <article class="detail-card ready">
        <span>Ready / caution decisions</span>
        <div class="detail-score">${ready}</div>
        <p>These can proceed only when action approval rules are satisfied.</p>
      </article>
      <article class="detail-card blocked">
        <span>Blocked / not ready</span>
        <div class="detail-score">${blocked}</div>
        <p>These need more evidence before execution or leadership claims.</p>
      </article>
    </div>
    ${renderDecisionCards()}
  `;
}

function renderContent() {
  if (!state) return;
  setHeader();
  const renderers = {
    incident: () => `${renderRisk()}${renderTimeline()}`,
    risk: renderRisk,
    decisions: renderDecisionCards,
    matrix: renderMatrix,
    integrity: renderIntegrity,
    missing: renderMissing,
    blast: renderBlast,
    audit: renderAudit,
    timeline: renderTimeline,
  };
  els.content.innerHTML = (renderers[view] || renderRisk)();
}

async function loadState() {
  state = await requestJson("/state");
  renderContent();
}

async function approveDecision(decisionId) {
  await requestJson("/approval", {
    method: "POST",
    body: JSON.stringify({ decision_id: decisionId, approval: "approved" }),
  });
  await loadState();
}

async function executeAction(actionId) {
  await requestJson("/respond", {
    method: "POST",
    body: JSON.stringify({ action: actionId }),
  });
  await loadState();
}

async function exportBrief() {
  const payload = await requestJson("/brief");
  els.briefOutput.textContent = payload.brief;
  els.briefDialog.showModal();
}

async function runCustom(event) {
  event.preventDefault();
  els.customResult.textContent = "Running request...";
  const result = await requestJson("/custom-run", {
    method: "POST",
    body: JSON.stringify({
      title: els.customTitle.value,
      action: els.customAction.value,
      evidence: els.customEvidence.value,
      execute: els.customExecute.checked,
    }),
  });
  state = result;
  const feedback = result.integration?.request?.feedback;
  els.customResult.innerHTML = feedback
    ? `<strong>${feedback.executed ? "Executed" : "Held"}: ${escapeHtml(feedback.action_label)}</strong><span>${escapeHtml(feedback.message)}</span><span>Readiness: ${feedback.readiness ?? "n/a"}%</span>`
    : escapeHtml(result.message || "Request complete.");
  renderContent();
}

function bindEvents() {
  els.refreshBtn.addEventListener("click", () => loadState().catch((error) => alert(error.message)));
  els.exportBriefBtn.addEventListener("click", () => exportBrief().catch((error) => alert(error.message)));
  els.runCustomBtn.addEventListener("click", () => els.form.scrollIntoView({ behavior: "smooth", block: "center" }));
  els.closeBriefBtn.addEventListener("click", () => els.briefDialog.close());
  els.form.addEventListener("submit", (event) => runCustom(event).catch((error) => {
    els.customResult.textContent = error.message;
  }));
  els.form.addEventListener("click", (event) => {
    const scenario = event.target.closest("[data-evidence]");
    if (!scenario) return;
    els.customTitle.value = scenario.dataset.title;
    els.customAction.value = scenario.dataset.action;
    els.customEvidence.value = scenario.dataset.evidence;
    els.customResult.textContent = "Scenario loaded. Click Run request.";
  });
  els.content.addEventListener("click", (event) => {
    const approve = event.target.closest("[data-approve]")?.dataset.approve;
    const execute = event.target.closest("[data-execute]")?.dataset.execute;
    const viewChecks = event.target.closest("[data-view-checks]")?.dataset.viewChecks;
    const exportBriefClick = event.target.closest("[data-export-brief]");
    if (approve) approveDecision(approve).catch((error) => alert(error.message));
    if (execute) executeAction(execute).catch((error) => alert(error.message));
    if (viewChecks) window.location.href = `detail.html?view=matrix&decision=${encodeURIComponent(viewChecks)}`;
    if (exportBriefClick) exportBrief().catch((error) => alert(error.message));
  });
}

bindEvents();
loadState().catch((error) => {
  els.content.innerHTML = `<article class="detail-card blocked"><h3>Unable to load detail</h3><p>${escapeHtml(error.message)}</p></article>`;
});
