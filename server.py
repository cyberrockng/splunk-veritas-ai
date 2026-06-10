from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import base64
import json
import os
import ssl
import time
from urllib import parse, request
from urllib.parse import urlparse


ROOT = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", "5173"))
SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "").rstrip("/")
SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN", "")
SPLUNK_AUTH_SCHEME = os.environ.get("SPLUNK_AUTH_SCHEME", "Bearer")
SPLUNK_VERIFY_SSL = os.environ.get("SPLUNK_VERIFY_SSL", "true").lower() not in {"0", "false", "no"}
SPLUNK_TIMEOUT = int(os.environ.get("SPLUNK_TIMEOUT", "8"))
SPLUNK_MAX_RESULTS = int(os.environ.get("SPLUNK_MAX_RESULTS", "25"))
SPLUNK_EARLIEST = os.environ.get("SPLUNK_EARLIEST", "-60m")
SPLUNK_LATEST = os.environ.get("SPLUNK_LATEST", "now")
VERITAS_SPLUNK_INDEX = os.environ.get("VERITAS_SPLUNK_INDEX", "veritas")
VERITAS_INCIDENT_ID = os.environ.get("VERITAS_INCIDENT_ID", "INC-001")
VERITAS_SOURCETYPE = os.environ.get("VERITAS_SOURCETYPE", "veritas:incident")


ATTACK_EVENTS = [
    {
        "id": "SEC-3001",
        "time": "10:41:03",
        "source": "splunk:index=auth",
        "query": "index=auth user=admin@northstar.health action=login earliest=-30m | table _time user src_ip geo result",
        "summary": "Admin user logged in successfully from Lagos, NG using trusted device fingerprint.",
        "user": "admin@northstar.health",
        "src_ip": "102.89.44.21",
        "geo": "Lagos, NG",
        "severity": "info",
        "tags": ["auth", "login", "baseline"],
    },
    {
        "id": "SEC-3002",
        "time": "10:44:18",
        "source": "splunk:index=auth",
        "query": "index=auth user=admin@northstar.health action=login earliest=-30m | iplocation src_ip | transaction user maxspan=10m",
        "summary": "Same admin account logged in from Frankfurt, DE three minutes after Lagos login.",
        "user": "admin@northstar.health",
        "src_ip": "185.199.108.47",
        "geo": "Frankfurt, DE",
        "severity": "high",
        "tags": ["auth", "impossible-travel", "identity"],
    },
    {
        "id": "SEC-3003",
        "time": "10:45:02",
        "source": "splunk:index=identity",
        "query": "index=identity user=admin@northstar.health action=mfa_challenge OR action=mfa_push | stats count by result src_ip",
        "summary": "MFA push approved from unfamiliar ASN after two denied prompts.",
        "user": "admin@northstar.health",
        "src_ip": "185.199.108.47",
        "geo": "Frankfurt, DE",
        "severity": "high",
        "tags": ["mfa", "identity", "suspicious-asn"],
    },
    {
        "id": "SEC-3004",
        "time": "10:47:11",
        "source": "splunk:index=iam",
        "query": "index=iam user=admin@northstar.health action=role_grant role=super_admin | table _time user role actor src_ip",
        "summary": "Admin account granted itself super_admin role from the suspicious session.",
        "user": "admin@northstar.health",
        "src_ip": "185.199.108.47",
        "geo": "Frankfurt, DE",
        "severity": "critical",
        "tags": ["iam", "privilege-escalation"],
    },
    {
        "id": "SEC-3005",
        "time": "10:49:36",
        "source": "splunk:index=api_gateway",
        "query": "index=api_gateway user=admin@northstar.health endpoint=/api/patient/export status=200 | stats count sum(bytes) by user src_ip",
        "summary": "Sensitive patient export endpoint returned 200 with 42 MB response body.",
        "user": "admin@northstar.health",
        "src_ip": "185.199.108.47",
        "geo": "Frankfurt, DE",
        "severity": "critical",
        "tags": ["api", "data-exfiltration", "patient-data"],
    },
    {
        "id": "SEC-3006",
        "time": "10:50:09",
        "source": "splunk:index=edr",
        "query": "index=edr user=admin@northstar.health process=curl OR process=python | table _time host process command_line",
        "summary": "EDR observed scripted download tooling on an admin workstation session.",
        "user": "admin@northstar.health",
        "src_ip": "185.199.108.47",
        "geo": "Frankfurt, DE",
        "severity": "high",
        "tags": ["edr", "automation", "exfiltration"],
    },
]


DETECTION_RULES = [
    {
        "id": "DET-4101",
        "name": "Impossible travel admin login",
        "severity": "High",
        "confidence": 92,
        "requires": ["SEC-3001", "SEC-3002"],
        "risk": 24,
        "finding": "The same admin account authenticated from Lagos and Frankfurt within three minutes.",
        "response": "Revoke the suspicious session and force credential reset.",
    },
    {
        "id": "DET-4102",
        "name": "MFA fatigue followed by approval",
        "severity": "High",
        "confidence": 84,
        "requires": ["SEC-3003"],
        "risk": 18,
        "finding": "MFA was denied twice, then approved from an unfamiliar ASN.",
        "response": "Disable push approval for the account and require step-up verification.",
    },
    {
        "id": "DET-4103",
        "name": "Privilege escalation from suspicious session",
        "severity": "Critical",
        "confidence": 95,
        "requires": ["SEC-3004"],
        "risk": 28,
        "finding": "The suspicious admin session granted itself super_admin privileges.",
        "response": "Disable the account and remove the unauthorized role grant.",
    },
    {
        "id": "DET-4104",
        "name": "Sensitive patient export",
        "severity": "Critical",
        "confidence": 89,
        "requires": ["SEC-3005", "SEC-3006"],
        "risk": 30,
        "finding": "The suspicious session accessed patient export data and scripted download tooling appeared.",
        "response": "Block the source IP, revoke tokens, and open a data exposure incident.",
    },
]


RESPONSE_ACTIONS = [
    {
        "id": "revoke-token",
        "label": "Revoke session token",
        "effect": 25,
        "summary": "Killed active sessions for admin@northstar.health.",
    },
    {
        "id": "disable-account",
        "label": "Disable admin account",
        "effect": 32,
        "summary": "Disabled admin@northstar.health pending identity verification.",
    },
    {
        "id": "block-ip",
        "label": "Block source IP",
        "effect": 25,
        "summary": "Blocked 185.199.108.47 at the edge firewall.",
    },
    {
        "id": "open-incident",
        "label": "Open incident brief",
        "effect": 12,
        "summary": "Opened SEV-1 security incident and attached evidence timeline.",
    },
]

DECISION_POLICIES = [
    {
        "id": "revoke-session",
        "title": "Revoke session token",
        "description": "Kill active sessions for the suspicious admin account.",
        "impact": "Medium",
        "human_approval": True,
        "blast_radius": "May interrupt an active administrator, but the action is reversible and scoped to one account.",
        "recommended_action": "Approve token revocation and preserve auth evidence.",
        "checklist": [
            {
                "id": "suspicious-login",
                "label": "Suspicious login source",
                "evidence": ["SEC-3002"],
                "mandatory": True,
                "spl": "index=auth user=admin@northstar.health action=login earliest=-30m | iplocation src_ip | table _time user src_ip geo result",
            },
            {
                "id": "mfa-anomaly",
                "label": "MFA anomaly",
                "evidence": ["SEC-3003"],
                "mandatory": True,
                "spl": "index=identity user=admin@northstar.health action=mfa_challenge OR action=mfa_push | stats count by result src_ip",
            },
            {
                "id": "active-session-risk",
                "label": "Active risky session",
                "evidence": ["SEC-3002", "SEC-3005"],
                "mandatory": True,
                "spl": "index=auth user=admin@northstar.health src_ip=185.199.108.47 action=login OR action=session_refresh | table _time user src_ip action",
            },
        ],
    },
    {
        "id": "disable-admin",
        "title": "Disable admin account",
        "description": "Temporarily disable the admin account pending identity verification.",
        "impact": "High",
        "human_approval": True,
        "blast_radius": "May disrupt active recovery if this account is needed by the incident commander.",
        "recommended_action": "Approve with incident lead confirmation and prepare a break-glass account.",
        "checklist": [
            {
                "id": "suspicious-login",
                "label": "Suspicious login source",
                "evidence": ["SEC-3002"],
                "mandatory": True,
                "spl": "index=auth user=admin@northstar.health action=login earliest=-30m | iplocation src_ip | table _time user src_ip geo result",
            },
            {
                "id": "mfa-anomaly",
                "label": "MFA anomaly",
                "evidence": ["SEC-3003"],
                "mandatory": True,
                "spl": "index=identity user=admin@northstar.health action=mfa_challenge OR action=mfa_push | stats count by result src_ip",
            },
            {
                "id": "privilege-escalation",
                "label": "Privilege escalation",
                "evidence": ["SEC-3004"],
                "mandatory": True,
                "spl": "index=iam user=admin@northstar.health action=role_grant role=super_admin | table _time user role actor src_ip",
            },
            {
                "id": "abnormal-api",
                "label": "Abnormal sensitive API access",
                "evidence": ["SEC-3005"],
                "mandatory": False,
                "spl": "index=api_gateway user=admin@northstar.health endpoint=/api/patient/export | stats count sum(bytes) by user src_ip status",
            },
        ],
    },
    {
        "id": "block-source-ip",
        "title": "Block source IP",
        "description": "Block the suspicious source IP at the edge.",
        "impact": "High",
        "human_approval": True,
        "blast_radius": "Blocking a shared IP or cloud egress address may affect legitimate users.",
        "recommended_action": "Approve with caution. Check collateral impact before broad network blocking.",
        "checklist": [
            {
                "id": "suspicious-login",
                "label": "Suspicious login source",
                "evidence": ["SEC-3002"],
                "mandatory": True,
                "spl": "index=auth src_ip=185.199.108.47 | stats count by user action result",
            },
            {
                "id": "sensitive-access",
                "label": "Sensitive endpoint access",
                "evidence": ["SEC-3005"],
                "mandatory": True,
                "spl": "index=api_gateway src_ip=185.199.108.47 endpoint=/api/patient/export | stats count sum(bytes) by status",
            },
            {
                "id": "threat-intel",
                "label": "Threat intelligence or reputation check",
                "evidence": [],
                "mandatory": False,
                "spl": "index=threatintel ip=185.199.108.47 | stats latest(reputation), latest(provider), latest(category) by ip",
            },
        ],
    },
    {
        "id": "declare-no-data-access",
        "title": "Declare no sensitive data accessed",
        "description": "Tell leadership that no sensitive data was accessed.",
        "impact": "Critical",
        "human_approval": True,
        "blast_radius": "A premature no-data-access statement can create legal, compliance, and trust risk.",
        "recommended_action": "Block the declaration until export, object storage, and exfiltration evidence is reviewed.",
        "checklist": [
            {
                "id": "admin-api-reviewed",
                "label": "Admin API activity reviewed",
                "evidence": ["SEC-3005"],
                "mandatory": True,
                "negative": True,
                "spl": "index=api_gateway user=admin@northstar.health endpoint=/api/patient/export | stats count sum(bytes) by user src_ip status",
            },
            {
                "id": "export-events",
                "label": "Export/download events checked",
                "evidence": [],
                "mandatory": True,
                "spl": "index=veritas incident_id=INC-001 action=export OR action=download | stats count by user, src_ip, object, status",
            },
            {
                "id": "object-storage",
                "label": "Object storage access checked",
                "evidence": [],
                "mandatory": True,
                "spl": "index=veritas incident_id=INC-001 sourcetype=object_storage | stats count by user, bucket, object, action, status",
            },
            {
                "id": "exfil-indicators",
                "label": "Exfiltration indicators checked",
                "evidence": ["SEC-3006"],
                "mandatory": True,
                "negative": True,
                "spl": "index=edr user=admin@northstar.health process=curl OR process=python | table _time host process command_line",
            },
        ],
    },
    {
        "id": "close-contained",
        "title": "Close incident as contained",
        "description": "Mark the incident contained and move to post-incident review.",
        "impact": "Critical",
        "human_approval": True,
        "blast_radius": "Closing too early can leave active sessions, persistence, or data exposure unresolved.",
        "recommended_action": "Block closure until containment actions are complete and post-containment monitoring is clean.",
        "checklist": [
            {
                "id": "session-revoked",
                "label": "Session token revoked",
                "action": "revoke-token",
                "mandatory": True,
                "spl": "index=auth user=admin@northstar.health action=session_revoked | table _time user session_id status",
            },
            {
                "id": "account-disabled",
                "label": "Admin account disabled",
                "action": "disable-account",
                "mandatory": True,
                "spl": "index=identity user=admin@northstar.health action=disable_account | table _time user actor status",
            },
            {
                "id": "source-blocked",
                "label": "Source IP blocked",
                "action": "block-ip",
                "mandatory": True,
                "spl": "index=firewall src_ip=185.199.108.47 action=blocked | stats count by src_ip action",
            },
            {
                "id": "post-monitoring",
                "label": "Post-containment monitoring clean",
                "evidence": [],
                "mandatory": True,
                "spl": "index=veritas incident_id=INC-001 earliest=-30m | stats count by user, src_ip, action, status",
            },
        ],
    },
]


LAB_STATE = {
    "stage": "idle",
    "events": [],
    "detections": [],
    "actions": [],
    "last_splunk_load": None,
    "last_investigation": None,
}


def action_status():
    completed = {action["id"] for action in LAB_STATE["actions"]}
    return [
        {
            **action,
            "status": "completed" if action["id"] in completed else "pending",
        }
        for action in RESPONSE_ACTIONS
    ]


def completed_action_ids():
    return {action["id"] for action in LAB_STATE["actions"]}


def streamed_event_ids():
    return {event["id"] for event in LAB_STATE["events"]}


def event_source_category(event):
    return event["source"].replace("splunk:index=", "")


def event_prototype(event_id):
    return next((event for event in ATTACK_EVENTS if event["id"] == event_id), None)


def splunk_escape(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def veritas_base_search():
    return (
        f'index="{splunk_escape(VERITAS_SPLUNK_INDEX)}" '
        f'sourcetype="{splunk_escape(VERITAS_SOURCETYPE)}" '
        f'| spath | search incident_id="{splunk_escape(VERITAS_INCIDENT_ID)}"'
    )


def veritas_event_search(event_ids):
    quoted_ids = ", ".join(f'"{splunk_escape(event_id)}"' for event_id in event_ids)
    return (
        f"{veritas_base_search()} event_id IN ({quoted_ids}) "
        "| table _time event_id incident_id source_category summary user src_ip geo severity query tags"
    )


def row_value(row, *keys):
    for key in keys:
        value = row.get(key)
        if isinstance(value, list):
            value = value[0] if value else None
        if value is not None and value != "":
            return value
    return None


def row_raw_json(row):
    raw = row.get("_raw")
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if isinstance(parsed, dict) and isinstance(parsed.get("event"), dict):
        return parsed["event"]
    return parsed if isinstance(parsed, dict) else {}


def normalize_splunk_event(row):
    raw = row_raw_json(row)
    event_id = row_value(row, "event_id", "id") or raw.get("event_id") or raw.get("id")
    prototype = event_prototype(event_id)
    if prototype is None:
        return None

    source_category = (
        row_value(row, "source_category")
        or raw.get("source_category")
        or event_source_category(prototype)
    )
    tags = row_value(row, "tags") or raw.get("tags") or prototype.get("tags", [])
    if isinstance(tags, str):
        tags = [item.strip() for item in tags.split(",") if item.strip()]

    return {
        **prototype,
        "id": event_id,
        "time": row_value(row, "_time", "time") or raw.get("time") or prototype["time"],
        "source": f"splunk:index={source_category}",
        "query": row_value(row, "query") or raw.get("query") or prototype["query"],
        "summary": row_value(row, "summary") or raw.get("summary") or prototype["summary"],
        "user": row_value(row, "user") or raw.get("user") or prototype["user"],
        "src_ip": row_value(row, "src_ip") or raw.get("src_ip") or prototype["src_ip"],
        "geo": row_value(row, "geo") or raw.get("geo") or prototype["geo"],
        "severity": row_value(row, "severity") or raw.get("severity") or prototype["severity"],
        "tags": tags,
        "origin": "splunk-rest",
    }


def evidence_for_ids(ids):
    id_set = set(ids)
    return [event for event in LAB_STATE["events"] if event["id"] in id_set]


def evaluate_check(item):
    event_ids = streamed_event_ids()
    action_ids = completed_action_ids()
    required_events = item.get("evidence", [])
    required_action = item.get("action")
    negative = item.get("negative", False)

    if required_action:
        found = required_action in action_ids
        evidence = []
    else:
        evidence = evidence_for_ids(required_events)
        found = bool(evidence)

    if negative and found:
        status = "contradicted"
    elif found:
        status = "found"
    else:
        status = "missing"

    return {
        "id": item["id"],
        "label": item["label"],
        "mandatory": item.get("mandatory", False),
        "status": status,
        "found": found and not negative,
        "contradicted": found and negative,
        "evidence": evidence,
        "missing": not found,
        "spl": item["spl"],
    }


def decision_status(score, has_contradiction, missing_mandatory, impact):
    if has_contradiction:
        return "Blocked"
    if missing_mandatory:
        return "Not Ready"
    if impact == "High" and score < 90:
        return "Caution"
    if impact == "Critical" and score < 95:
        return "Caution"
    return "Approved"


def evaluate_decision(policy):
    checks = [evaluate_check(item) for item in policy["checklist"]]
    total = len(checks)
    positive = len([item for item in checks if item["status"] == "found"])
    contradicted = [item for item in checks if item["status"] == "contradicted"]
    missing = [item for item in checks if item["status"] == "missing"]
    missing_mandatory = [item for item in missing if item["mandatory"]]
    score = round((positive / total) * 100) if total else 0

    if contradicted:
        score = min(max(score, 38), 38)
    if missing_mandatory:
        score = min(score, 62)

    status = decision_status(
        score,
        bool(contradicted),
        bool(missing_mandatory),
        policy["impact"],
    )
    if policy["id"] == "block-source-ip" and status == "Approved":
        status = "Caution"
        score = min(score, 78)
    if policy["id"] == "declare-no-data-access" and status != "Blocked":
        status = "Blocked"
        score = min(score, 38)
    if policy["id"] == "close-contained" and status == "Approved":
        status = "Caution"

    reason = {
        "Approved": "Evidence threshold is met for this response decision.",
        "Caution": "Most evidence is present, but blast radius or residual uncertainty requires human review.",
        "Blocked": "This decision is unsafe because evidence contradicts it or mandatory evidence is missing.",
        "Not Ready": "Not enough required evidence has been collected yet.",
    }[status]

    return {
        "id": policy["id"],
        "title": policy["title"],
        "description": policy["description"],
        "impact": policy["impact"],
        "human_approval": policy["human_approval"],
        "status": status,
        "readiness": score,
        "reason": reason,
        "blast_radius": policy["blast_radius"],
        "recommended_action": policy["recommended_action"],
        "checks": checks,
        "found_evidence": [item for item in checks if item["status"] == "found"],
        "missing_evidence": missing + contradicted,
        "recommended_spl": [item["spl"] for item in missing + contradicted],
    }


def evaluate_decisions():
    return [evaluate_decision(policy) for policy in DECISION_POLICIES]


def evidence_integrity():
    required_sources = {
        "splunk:index=auth",
        "splunk:index=identity",
        "splunk:index=iam",
        "splunk:index=api_gateway",
        "splunk:index=edr",
        "splunk:index=object_storage",
        "splunk:index=dlp",
    }
    checked_sources = {event["source"] for event in LAB_STATE["events"]}
    missing_sources = sorted(required_sources - checked_sources)
    completeness = round((len(checked_sources) / len(required_sources)) * 100)
    latest = LAB_STATE["events"][-1]["time"] if LAB_STATE["events"] else "No events streamed"

    return {
        "freshness": latest,
        "sources_checked": sorted(checked_sources),
        "sources_missing": missing_sources,
        "telemetry_completeness": completeness,
        "source_trust": "High for indexed Splunk telemetry; low for user claims and raw log text.",
        "prompt_injection_warning": "Logs are treated as untrusted evidence, not instructions. Veritas does not follow instructions embedded inside log fields.",
        "missing_telemetry_warning": "Missing telemetry reduces readiness. Missing logs are never treated as proof of safety.",
        "human_approval_requirement": "High-impact decisions require evidence threshold plus human approval.",
    }


def calculate_risk():
    detection_risk = sum(detection["risk"] for detection in LAB_STATE["detections"])
    response_reduction = sum(action["effect"] for action in LAB_STATE["actions"])
    if not LAB_STATE["events"]:
        return 12
    return max(8, min(100, 18 + detection_risk - response_reduction))


def run_detections():
    event_ids = {event["id"] for event in LAB_STATE["events"]}
    LAB_STATE["detections"] = [
        rule for rule in DETECTION_RULES if all(event_id in event_ids for event_id in rule["requires"])
    ]
    if LAB_STATE["detections"] and LAB_STATE["stage"] not in {"responding", "contained"}:
        LAB_STATE["stage"] = "investigated"


def find_events_by_ids(ids):
    id_set = set(ids)
    return [event for event in ATTACK_EVENTS if event["id"] in id_set]


def search_events(query):
    exact_matches = [event for event in ATTACK_EVENTS if event["query"] == query]
    if exact_matches:
        return exact_matches

    return [
        event
        for event in LAB_STATE["events"]
        if event["source"].replace("splunk:", "") in query
        or any(tag in query for tag in event["tags"])
        or event["user"] in query
    ]


def splunk_configured():
    return bool(SPLUNK_HOST and SPLUNK_TOKEN)


def splunk_status():
    return {
        "provider": "splunk-rest" if splunk_configured() else "mock-mcp",
        "configured": splunk_configured(),
        "host": SPLUNK_HOST or None,
        "index": VERITAS_SPLUNK_INDEX,
        "incident_id": VERITAS_INCIDENT_ID,
        "sourcetype": VERITAS_SOURCETYPE,
        "auth_scheme": SPLUNK_AUTH_SCHEME if SPLUNK_TOKEN else None,
        "verify_ssl": SPLUNK_VERIFY_SSL,
        "max_results": SPLUNK_MAX_RESULTS,
        "earliest": SPLUNK_EARLIEST,
        "latest": SPLUNK_LATEST,
        "last_load": LAB_STATE.get("last_splunk_load"),
    }


def splunk_context():
    if SPLUNK_VERIFY_SSL:
        return None
    return ssl._create_unverified_context()


def splunk_auth_header():
    if SPLUNK_AUTH_SCHEME.lower() == "basic":
        encoded = base64.b64encode(SPLUNK_TOKEN.encode("utf-8")).decode("ascii")
        return f"Basic {encoded}"
    return f"{SPLUNK_AUTH_SCHEME} {SPLUNK_TOKEN}"


def splunk_request(path, params=None, method="GET"):
    if not splunk_configured():
        raise RuntimeError("Splunk is not configured")

    params = params or {}
    encoded = parse.urlencode(params).encode("utf-8")
    url = f"{SPLUNK_HOST}{path}"

    if method == "GET" and encoded:
        url = f"{url}?{encoded.decode('utf-8')}"
        data = None
    else:
        data = encoded if method == "POST" else None

    req = request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": splunk_auth_header(),
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    with request.urlopen(req, timeout=SPLUNK_TIMEOUT, context=splunk_context()) as response:
        body = response.read().decode("utf-8")
    return json.loads(body) if body else {}


def splunk_search(query, earliest=SPLUNK_EARLIEST, latest=SPLUNK_LATEST, count=None):
    search_text = query.strip()
    if not search_text.startswith("|") and not search_text.startswith("search "):
        search_text = f"search {search_text}"

    created = splunk_request(
        "/services/search/jobs",
        {
            "search": search_text,
            "earliest_time": earliest,
            "latest_time": latest,
            "output_mode": "json",
        },
        method="POST",
    )
    sid = created.get("sid")
    if not sid:
        raise RuntimeError("Splunk did not return a search SID")

    quoted_sid = parse.quote(sid, safe="")
    dispatch_state = "QUEUED"
    for _ in range(5):
        status = splunk_request(
            f"/services/search/jobs/{quoted_sid}",
            {"output_mode": "json"},
        )
        entry = (status.get("entry") or [{}])[0]
        content = entry.get("content", {})
        dispatch_state = content.get("dispatchState", dispatch_state)
        if content.get("isDone") or dispatch_state == "DONE":
            break
        time.sleep(0.4)

    results = splunk_request(
        f"/services/search/jobs/{quoted_sid}/results",
        {
            "output_mode": "json",
            "count": count or SPLUNK_MAX_RESULTS,
        },
    )
    rows = results.get("results", [])
    return {
        "provider": "splunk-rest",
        "job_id": sid,
        "result_count": len(rows),
        "rows": rows,
        "dispatch_state": dispatch_state,
        "link": f"{SPLUNK_HOST}/app/search/search?sid={parse.quote(sid)}",
    }


def search_job_id(detection_id, index):
    return f"sid_veritas_{detection_id.lower()}_{index:03d}"


def mcp_tool_call(tool, arguments, result):
    return {
        "tool": tool,
        "arguments": arguments,
        "result": result,
    }


def execute_detection_search(detection, query, evidence, index):
    fallback_job_id = search_job_id(detection["id"], index)
    fallback = {
        "provider": "mock-mcp",
        "job_id": fallback_job_id,
        "result_count": len(evidence),
        "event_ids": [event["id"] for event in evidence],
        "link": f"splunk://search/{fallback_job_id}",
        "rows": [],
    }

    if not splunk_configured():
        return fallback

    try:
        result = splunk_search(query)
        return {
            **result,
            "event_ids": [event["id"] for event in evidence],
            "fallback_result_count": len(evidence),
        }
    except Exception as error:
        return {
            **fallback,
            "provider": "mock-mcp-fallback",
            "error": str(error),
        }


def load_splunk_evidence():
    if not splunk_configured():
        return {
            "ok": False,
            "error": "Splunk REST is not configured. Set SPLUNK_HOST and SPLUNK_TOKEN, then restart the server.",
        }

    event_ids = [event["id"] for event in ATTACK_EVENTS]
    query = veritas_event_search(event_ids)
    search_result = splunk_search(
        query,
        earliest=SPLUNK_EARLIEST,
        latest=SPLUNK_LATEST,
        count=max(len(event_ids), SPLUNK_MAX_RESULTS),
    )
    events_by_id = {}
    for row in search_result["rows"]:
        event = normalize_splunk_event(row)
        if event:
            events_by_id[event["id"]] = {
                **event,
                "splunk_job_id": search_result["job_id"],
                "splunk_result_link": search_result["link"],
            }

    ordered_events = [events_by_id[event_id] for event_id in event_ids if event_id in events_by_id]
    LAB_STATE["stage"] = "splunk-evidence-loaded" if ordered_events else "idle"
    LAB_STATE["events"] = ordered_events
    LAB_STATE["detections"] = []
    LAB_STATE["actions"] = []
    LAB_STATE["last_splunk_load"] = {
        "query": query,
        "job_id": search_result["job_id"],
        "provider": search_result["provider"],
        "result_count": search_result["result_count"],
        "mapped_events": len(ordered_events),
        "missing_events": [event_id for event_id in event_ids if event_id not in events_by_id],
        "link": search_result["link"],
        "dispatch_state": search_result.get("dispatch_state"),
    }

    return {
        "ok": True,
        **state_payload(),
        "search": LAB_STATE["last_splunk_load"],
    }


def state_payload():
    return {
        "stage": LAB_STATE["stage"],
        "events": LAB_STATE["events"],
        "detections": LAB_STATE["detections"],
        "decisions": evaluate_decisions(),
        "integrity": evidence_integrity(),
        "actions": action_status(),
        "risk": calculate_risk(),
        "integration": splunk_status(),
    }


def investigation_payload():
    run_detections()
    searches = []
    tool_calls = []
    for index, detection in enumerate(LAB_STATE["detections"], start=1):
        evidence = evidence_for_ids(detection["requires"]) or find_events_by_ids(detection["requires"])
        query = veritas_event_search(detection["requires"]) if splunk_configured() else evidence[-1]["query"]
        search_result = execute_detection_search(detection, query, evidence, index)
        searches.append(
            {
                "detection": detection["id"],
                "query": query,
                "job_id": search_result["job_id"],
                "provider": search_result["provider"],
                "result_link": search_result["link"],
                "matched_events": evidence,
                "match_count": search_result["result_count"],
                "fallback_match_count": len(evidence),
                "error": search_result.get("error"),
            }
        )
        tool_calls.append(
            mcp_tool_call(
                "splunk.search",
                {
                    "query": query,
                    "earliest": SPLUNK_EARLIEST,
                    "latest": SPLUNK_LATEST,
                },
                {
                    "provider": search_result["provider"],
                    "job_id": search_result["job_id"],
                    "result_count": search_result["result_count"],
                    "event_ids": search_result.get("event_ids", []),
                    "link": search_result["link"],
                    "error": search_result.get("error"),
                },
            )
        )

    for detection in LAB_STATE["detections"]:
        tool_calls.append(
            mcp_tool_call(
                "splunk.notable_event",
                {
                    "rule": detection["name"],
                    "severity": detection["severity"],
                    "evidence": detection["requires"],
                },
                {
                    "notable_id": f"NE-{detection['id'].split('-')[-1]}",
                    "status": "created",
                },
            )
        )

    tool_calls.append(
        mcp_tool_call(
            "splunk.risk_score",
            {
                "entity": "admin@northstar.health",
                "detections": [detection["id"] for detection in LAB_STATE["detections"]],
            },
            {
                "risk_score": calculate_risk(),
                "risk_object": "admin@northstar.health",
            },
        )
    )

    LAB_STATE["last_investigation"] = {
        "searches": searches,
        "tool_calls": tool_calls,
        "summary": "Veritas correlated identity, IAM, API gateway, and EDR logs into a probable account takeover.",
    }

    return {
        **state_payload(),
        "searches": searches,
        "tool_calls": tool_calls,
        "summary": LAB_STATE["last_investigation"]["summary"],
    }


def brief_text():
    decisions = evaluate_decisions()
    approved = [item for item in decisions if item["status"] in {"Approved", "Caution"}]
    blocked = [item for item in decisions if item["status"] in {"Blocked", "Not Ready"}]
    integrity = evidence_integrity()
    last_load = LAB_STATE.get("last_splunk_load") or {}
    last_investigation = LAB_STATE.get("last_investigation") or {}
    investigation_searches = last_investigation.get("searches", [])

    def line_or_default(lines, default):
        return "\n".join(lines) if lines else default

    detection_lines = "\n".join(
        f"- {item['id']} {item['name']}: {item['finding']}" for item in LAB_STATE["detections"]
    )
    approved_lines = line_or_default(
        [
            f"- {item['title']}: {item['status']} ({item['readiness']}%). {item['reason']}"
            for item in approved
        ],
        "- No approved or caution-ready decisions.",
    )
    blocked_lines = line_or_default(
        [
            f"- {item['title']}: {item['status']} ({item['readiness']}%). {item['reason']}"
            for item in blocked
        ],
        "- No blocked or not-ready decisions.",
    )
    missing_lines = "\n".join(
        f"- {decision['title']}: {check['label']} -> {check['spl']}"
        for decision in decisions
        for check in decision["missing_evidence"]
    )
    action_lines = "\n".join(
        f"- {item['label']}: {item['summary']}" for item in LAB_STATE["actions"]
    )
    event_lines = "\n".join(
        f"- {event['time']} {event['id']} {event['summary']}" for event in LAB_STATE["events"]
    )
    evidence_job_lines = line_or_default(
        [
            f"- {event['id']}: job={event.get('splunk_job_id', 'mock')}, source={event['source']}, link={event.get('splunk_result_link', 'n/a')}"
            for event in LAB_STATE["events"]
        ],
        "- No evidence search jobs recorded.",
    )
    detection_job_lines = line_or_default(
        [
            f"- {item['detection']}: provider={item['provider']}, job={item['job_id']}, results={item['match_count']}, link={item['result_link']}"
            for item in investigation_searches
        ],
        "- No threshold search jobs recorded.",
    )
    load_line = (
        f"Evidence load search: provider={last_load.get('provider')}, job={last_load.get('job_id')}, "
        f"mapped={last_load.get('mapped_events')}, missing={', '.join(last_load.get('missing_events') or []) or 'none'}, "
        f"link={last_load.get('link')}"
        if last_load
        else "Evidence load search: mock evidence path or not recorded."
    )
    source_lines = "\n".join(
        [
            f"- Sources checked: {', '.join(integrity.get('sources_checked') or []) or 'none'}",
            f"- Sources missing: {', '.join(integrity.get('sources_missing') or []) or 'none'}",
            f"- Telemetry completeness: {integrity.get('telemetry_completeness', 0)}%",
            f"- Evidence freshness: {integrity.get('freshness')}",
        ]
    )

    return f"""Veritas AI Decision Audit Brief

Incident: Admin account takeover and patient export attempt
Generated by Veritas AI
Adapter mode: Backend API
Search provider: {splunk_status()["provider"]}
Splunk index: {splunk_status()["index"]}
Incident ID: {splunk_status()["incident_id"]}
Risk score: {calculate_risk()}/100
MCP tool calls: splunk.search, splunk.notable_event, splunk.risk_score

Executive decision summary:
- Containment actions were approved where the evidence threshold was met.
- Premature data-access and closure statements remain blocked until missing evidence is collected.
- Missing telemetry is treated as uncertainty, not proof of safety.

Approved or caution-ready decisions:
{approved_lines}

Blocked or not-ready decisions:
{blocked_lines}

Detections:
{detection_lines or "- No detections yet."}

Splunk evidence provenance:
{load_line}

Evidence event jobs:
{evidence_job_lines}

Threshold search jobs:
{detection_job_lines}

Evidence source coverage:
{source_lines}

Missing evidence and SPL to close gaps:
{missing_lines or "- No missing decision evidence."}

Containment actions:
{action_lines or "- No containment actions executed yet."}

Evidence timeline:
{event_lines or "- No attack events streamed yet."}

Recommended next steps:
1. Preserve auth, IAM, API gateway, and EDR evidence.
2. Rotate admin credentials and review all privileged role grants.
3. Validate patient export scope before external reporting.
4. Keep source IP block active while threat intelligence review runs.
"""


class VeritasHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/api/health":
            self.send_json({"ok": True, "adapter": "backend-api", "mode": "veritas-threshold-engine"})
            return

        if path == "/api/sentinel/state":
            self.send_json(state_payload())
            return

        if path == "/api/sentinel/config":
            self.send_json(splunk_status())
            return

        if path == "/api/sentinel/brief":
            self.send_json({"brief": brief_text()})
            return

        super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path

        try:
            payload = self.read_json()
        except json.JSONDecodeError:
            self.send_json({"error": "Invalid JSON"}, status=400)
            return

        if path == "/api/sentinel/reset":
            LAB_STATE["stage"] = "idle"
            LAB_STATE["events"] = []
            LAB_STATE["detections"] = []
            LAB_STATE["actions"] = []
            LAB_STATE["last_splunk_load"] = None
            LAB_STATE["last_investigation"] = None
            self.send_json(state_payload())
            return

        if path == "/api/sentinel/start":
            LAB_STATE["stage"] = "attack-running"
            LAB_STATE["events"] = []
            LAB_STATE["detections"] = []
            LAB_STATE["actions"] = []
            LAB_STATE["last_splunk_load"] = None
            LAB_STATE["last_investigation"] = None
            self.send_json({**state_payload(), "sequence_length": len(ATTACK_EVENTS)})
            return

        if path == "/api/sentinel/load-splunk":
            result = load_splunk_evidence()
            self.send_json(result, status=200 if result.get("ok") else 400)
            return

        if path == "/api/sentinel/step":
            if LAB_STATE["stage"] == "idle":
                LAB_STATE["stage"] = "attack-running"
            if len(LAB_STATE["events"]) < len(ATTACK_EVENTS):
                LAB_STATE["events"].append(ATTACK_EVENTS[len(LAB_STATE["events"])])
            if len(LAB_STATE["events"]) == len(ATTACK_EVENTS):
                LAB_STATE["stage"] = "attack-complete"
            self.send_json(state_payload())
            return

        if path == "/api/sentinel/investigate":
            self.send_json(investigation_payload())
            return

        if path == "/api/sentinel/respond":
            action_id = payload.get("action")
            action = next((item for item in RESPONSE_ACTIONS if item["id"] == action_id), None)
            if action is None:
                self.send_json({"error": "Unknown response action"}, status=400)
                return
            if action_id not in {item["id"] for item in LAB_STATE["actions"]}:
                LAB_STATE["actions"].append(action)
            LAB_STATE["stage"] = "contained" if calculate_risk() <= 35 else "responding"
            self.send_json(state_payload())
            return

        if path == "/api/sentinel/search":
            query = payload.get("query", "")
            self.send_json({"query": query, "events": search_events(query)})
            return

        self.send_json({"error": "Not found"}, status=404)


if __name__ == "__main__":
    os.chdir(ROOT)
    server = ThreadingHTTPServer(("127.0.0.1", PORT), VeritasHandler)
    print(f"Veritas AI server running at http://127.0.0.1:{PORT}")
    server.serve_forever()
