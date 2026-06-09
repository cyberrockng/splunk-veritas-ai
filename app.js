const evidenceEvents = [
  {
    id: "EVT-1001",
    time: "09:02:14",
    source: "splunk:index=deployments",
    query: 'index=deployments service=patient-portal earliest=-2h | table _time version actor status',
    summary: "patient-portal v3.8.1 deployed to production 7 minutes before error rate increased.",
    weight: 0.86,
    tags: ["deployment", "patient-portal"],
  },
  {
    id: "EVT-1002",
    time: "09:09:47",
    source: "splunk:index=apm",
    query: 'index=apm service=patient-portal status>=500 | timechart count by endpoint',
    summary: "HTTP 500 errors increased on /appointments/confirm after deployment; database latency stayed normal.",
    weight: 0.91,
    tags: ["apm", "appointments"],
  },
  {
    id: "EVT-1003",
    time: "09:11:02",
    source: "splunk:index=db_metrics",
    query: 'index=db_metrics db=patient_records | stats avg(cpu), p95(query_ms), max(conn_pool)',
    summary: "Database CPU, query latency, and connection pool stayed within normal operating range.",
    weight: 0.89,
    tags: ["database"],
  },
  {
    id: "EVT-1004",
    time: "09:14:33",
    source: "splunk:index=portal_access",
    query: 'index=portal_access action=appointment_submit result=failure | stats dc(user_id), count by device',
    summary: "1,286 patients failed appointment submission, with failures concentrated on mobile clients.",
    weight: 0.94,
    tags: ["patient-impact", "mobile"],
  },
  {
    id: "EVT-1005",
    time: "09:17:26",
    source: "splunk:index=auth",
    query: 'index=auth user_type=admin action=login earliest=-1h | anomalydetection user src_ip',
    summary: "Privileged admin login from unusual ASN occurred during the incident window.",
    weight: 0.72,
    tags: ["identity", "security"],
  },
  {
    id: "EVT-1006",
    time: "09:19:40",
    source: "splunk:index=api_gateway",
    query: 'index=api_gateway endpoint=/patient/profile method=GET status=200 | stats count by actor role',
    summary: "Customer profile endpoint was accessed by the same admin role after the anomalous login.",
    weight: 0.67,
    tags: ["data-access", "security"],
  },
  {
    id: "EVT-1007",
    time: "09:20:18",
    source: "splunk:index=backups",
    query: 'index=backups system=patient_records | latest(validation_status), latest(snapshot_id)',
    summary: "Backup job finished, but no validation success event exists for the latest snapshot.",
    weight: 0.82,
    tags: ["backup", "recovery"],
  },
  {
    id: "EVT-1008",
    time: "09:25:01",
    source: "splunk:index=migrations",
    query: 'index=migrations service=patient-portal version=3.8.1 | table irreversible rollback_plan',
    summary: "Deployment included an irreversible schema migration; rollback plan does not cover appointment token changes.",
    weight: 0.88,
    tags: ["rollback", "change"],
  },
  {
    id: "EVT-1009",
    time: "09:29:49",
    source: "splunk:index=support",
    query: 'index=support product=patient_portal | timechart count by topic',
    summary: "Support contacts increased 43% for appointment confirmation and login-loop complaints.",
    weight: 0.79,
    tags: ["support", "patient-impact"],
  },
];

const seedClaims = [
  {
    id: "CLM-1",
    text: "The database caused the outage.",
    verdict: "pending",
  },
  {
    id: "CLM-2",
    text: "No patients are affected.",
    verdict: "pending",
  },
  {
    id: "CLM-3",
    text: "No patient data was accessed.",
    verdict: "pending",
  },
  {
    id: "CLM-4",
    text: "Rollback is safe.",
    verdict: "pending",
  },
  {
    id: "CLM-5",
    text: "The backup completed successfully.",
    verdict: "pending",
  },
];

const claimRules = [
  {
    match: ["database", "db"],
    verdict: "contradicted",
    confidence: 87,
    evidence: ["EVT-1002", "EVT-1003", "EVT-1001"],
    risk: "High",
    finding:
      "The database is a weak explanation. Service errors rose after the portal deployment while DB health stayed normal.",
    recommendation:
      "Investigate patient-portal v3.8.1 and appointment confirmation paths before touching the database.",
  },
  {
    match: ["no patients", "no users", "not affected", "no citizen"],
    verdict: "contradicted",
    confidence: 94,
    evidence: ["EVT-1004", "EVT-1009"],
    risk: "Critical",
    finding:
      "Patient impact is confirmed. Appointment submissions are failing and support contacts increased sharply.",
    recommendation:
      "Declare patient-impacting incident, notify support, and prioritize appointment confirmation recovery.",
  },
  {
    match: ["no patient data", "no data", "data was not", "data access"],
    verdict: "uncertain",
    confidence: 61,
    evidence: ["EVT-1005", "EVT-1006"],
    risk: "Critical",
    finding:
      "The claim is not proven. There was anomalous privileged access and profile endpoint activity in the incident window.",
    recommendation:
      "Do not report no data exposure yet. Pull database audit logs and endpoint telemetry, then verify access scope.",
  },
  {
    match: ["rollback", "roll back", "revert"],
    verdict: "contradicted",
    confidence: 83,
    evidence: ["EVT-1008", "EVT-1001"],
    risk: "High",
    finding:
      "Rollback is risky because the deployment included an irreversible schema migration not covered by the rollback plan.",
    recommendation:
      "Use a forward fix or feature-flag disablement for appointment confirmation before rollback.",
  },
  {
    match: ["backup", "restore", "snapshot"],
    verdict: "uncertain",
    confidence: 74,
    evidence: ["EVT-1007"],
    risk: "High",
    finding:
      "The backup job finished, but successful validation is missing. Completion is not the same as recoverability.",
    recommendation:
      "Run backup validation before any destructive remediation or public recovery assurance.",
  },
  {
    match: ["vendor", "third party", "external"],
    verdict: "uncertain",
    confidence: 52,
    evidence: ["EVT-1002", "EVT-1004"],
    risk: "Medium",
    finding:
      "Current evidence points to the portal confirmation path, but vendor impact has not been fully ruled out.",
    recommendation:
      "Verify upstream appointment API and mobile gateway logs before assigning responsibility to a vendor.",
  },
];

let claims = seedClaims.map((claim) => ({ ...claim }));
let selectedEvidence = null;

const claimCards = document.querySelector("#claimCards");
const evidenceList = document.querySelector("#evidenceList");
const timeline = document.querySelector("#timeline");
const truthScore = document.querySelector("#truthScore");
const truthSummary = document.querySelector("#truthSummary");
const claimsChecked = document.querySelector("#claimsChecked");
const claimsContradicted = document.querySelector("#claimsContradicted");
const evidenceCount = document.querySelector("#evidenceCount");
const riskLevel = document.querySelector("#riskLevel");
const claimForm = document.querySelector("#claimForm");
const claimInput = document.querySelector("#claimInput");
const verifyAllBtn = document.querySelector("#verifyAllBtn");
const exportBriefBtn = document.querySelector("#exportBriefBtn");
const briefDialog = document.querySelector("#briefDialog");
const closeBriefBtn = document.querySelector("#closeBriefBtn");
const briefOutput = document.querySelector("#briefOutput");

function normalize(text) {
  return text.toLowerCase().replace(/[^a-z0-9\s-]/g, "");
}

function verifyClaim(claim) {
  const normalized = normalize(claim.text);
  const rule = claimRules.find((candidate) =>
    candidate.match.some((phrase) => normalized.includes(phrase)),
  );

  if (!rule) {
    return {
      ...claim,
      verdict: "uncertain",
      confidence: 48,
      evidence: ["EVT-1001", "EVT-1002"],
      risk: "Medium",
      finding:
        "Veritas does not have enough direct evidence for this claim from the current source set.",
      recommendation:
        "Ask a narrower claim or connect the missing Splunk index so the truth card can be verified.",
    };
  }

  return {
    ...claim,
    verdict: rule.verdict,
    confidence: rule.confidence,
    evidence: rule.evidence,
    risk: rule.risk,
    finding: rule.finding,
    recommendation: rule.recommendation,
  };
}

function verifyAllClaims() {
  claims = claims.map(verifyClaim);
  render();
}

function getEvidenceById(id) {
  return evidenceEvents.find((event) => event.id === id);
}

function verdictLabel(verdict) {
  if (verdict === "supported") return "Supported";
  if (verdict === "contradicted") return "Contradicted";
  if (verdict === "uncertain") return "Uncertain";
  return "Pending";
}

function renderClaimCards() {
  claimCards.innerHTML = claims
    .map((claim) => {
      const evidenceButtons = (claim.evidence || [])
        .map((id) => `<button type="button" data-evidence="${id}">${id}</button>`)
        .join("");
      const confidence = claim.confidence ? `${claim.confidence}% confidence` : "Not checked";
      const finding = claim.finding || "Click Verify claims to check this assumption against evidence.";
      const recommendation = claim.recommendation || "No recommendation yet.";

      return `
        <article class="claim-card ${claim.verdict}">
          <div class="claim-card-header">
            <blockquote>${claim.text}</blockquote>
            <span class="verdict-pill ${claim.verdict}">${verdictLabel(claim.verdict)}</span>
          </div>
          <div class="claim-details">
            <p><strong>Finding:</strong> ${finding}</p>
            <p><strong>Decision risk:</strong> ${claim.risk || "Unknown"} | <strong>${confidence}</strong></p>
            <p><strong>Recommendation:</strong> ${recommendation}</p>
          </div>
          <div class="evidence-tags">${evidenceButtons}</div>
        </article>
      `;
    })
    .join("");
}

function renderEvidenceList() {
  evidenceList.innerHTML = evidenceEvents
    .map((event) => {
      const activeClass = selectedEvidence === event.id ? "active" : "";
      return `
        <article class="evidence-item ${activeClass}" id="${event.id}">
          <strong>${event.id} · ${event.time}</strong>
          <span>${event.source}</span>
          <code>${event.query}</code>
          <p>${event.summary}</p>
        </article>
      `;
    })
    .join("");
}

function renderTimeline() {
  timeline.innerHTML = evidenceEvents
    .slice()
    .sort((a, b) => a.time.localeCompare(b.time))
    .map(
      (event) => `
        <article class="timeline-item">
          <strong>${event.time}</strong>
          <p>${event.summary}</p>
        </article>
      `,
    )
    .join("");
}

function renderMetrics() {
  const checked = claims.filter((claim) => claim.verdict !== "pending");
  const contradicted = claims.filter((claim) => claim.verdict === "contradicted");
  const uncertain = claims.filter((claim) => claim.verdict === "uncertain");
  const supported = claims.filter((claim) => claim.verdict === "supported");
  const score = Math.max(
    0,
    Math.round(100 - contradicted.length * 18 - uncertain.length * 11 + supported.length * 4),
  );

  truthScore.textContent = checked.length ? score : 0;
  claimsChecked.textContent = checked.length;
  claimsContradicted.textContent = contradicted.length;
  evidenceCount.textContent = evidenceEvents.length;
  riskLevel.textContent = contradicted.length >= 2 || uncertain.length >= 2 ? "Critical" : "Medium";
  truthSummary.textContent = checked.length
    ? `${contradicted.length} claim(s) contradicted and ${uncertain.length} need more evidence before leadership acts.`
    : "Waiting for verification.";
}

function render() {
  renderClaimCards();
  renderEvidenceList();
  renderTimeline();
  renderMetrics();
}

function selectEvidence(id) {
  selectedEvidence = id;
  renderEvidenceList();
  const target = document.getElementById(id);
  if (target) {
    target.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}

function createBrief() {
  const checked = claims.filter((claim) => claim.verdict !== "pending");
  const contradicted = checked.filter((claim) => claim.verdict === "contradicted");
  const uncertain = checked.filter((claim) => claim.verdict === "uncertain");

  const cards = checked
    .map(
      (claim) => `- ${claim.text}
  Verdict: ${verdictLabel(claim.verdict)} (${claim.confidence}%)
  Risk if wrong: ${claim.risk}
  Finding: ${claim.finding}
  Recommendation: ${claim.recommendation}
  Evidence: ${(claim.evidence || []).join(", ")}`,
    )
    .join("\n\n");

  return `Splunk Veritas AI Decision Brief

Incident: Hospital patient portal degradation
Mode: War Room Truth Verification

Executive Summary:
Veritas checked ${checked.length} operational claim(s). ${contradicted.length} were contradicted by Splunk evidence and ${uncertain.length} remain unsafe to assert publicly. The safest next move is to treat this as patient-impacting, avoid database remediation, verify data access scope, and avoid rollback until migration risk is resolved.

Truth Cards:
${cards}

Recommended Next Actions:
1. Prioritize patient-portal appointment confirmation path.
2. Validate backup recoverability before destructive remediation.
3. Pull database audit logs before claiming no patient data exposure.
4. Avoid rollback until irreversible schema migration is addressed.
5. Publish support guidance acknowledging appointment submission failures.

Splunk Evidence Used:
${evidenceEvents.map((event) => `- ${event.id}: ${event.summary}`).join("\n")}`;
}

claimCards.addEventListener("click", (event) => {
  const button = event.target.closest("[data-evidence]");
  if (!button) return;
  selectEvidence(button.dataset.evidence);
});

claimForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const text = claimInput.value.trim();
  if (!text) return;
  claims = [
    {
      id: `CLM-${claims.length + 1}`,
      text,
      verdict: "pending",
    },
    ...claims,
  ].map((claim, index) => (index === 0 ? verifyClaim(claim) : claim));
  claimInput.value = "";
  render();
});

verifyAllBtn.addEventListener("click", verifyAllClaims);

exportBriefBtn.addEventListener("click", () => {
  if (!claims.some((claim) => claim.verdict !== "pending")) {
    verifyAllClaims();
  }
  briefOutput.textContent = createBrief();
  briefDialog.showModal();
});

closeBriefBtn.addEventListener("click", () => briefDialog.close());

render();
