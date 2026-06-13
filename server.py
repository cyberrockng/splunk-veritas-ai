from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import base64
from datetime import datetime, timezone
import json
import os
import ssl
import subprocess
import sys
import time
from types import SimpleNamespace
from urllib import parse, request
from urllib.parse import urlparse

from fetch_external_feed import DEFAULT_MANIFEST, build_payloads, normalize_sources, read_json


ROOT = os.path.dirname(os.path.abspath(__file__))
LAST_RUN_PATH = os.path.join(ROOT, ".veritas_last_run.json")
CASE_HISTORY_PATH = os.path.join(ROOT, ".veritas_case_history.json")


def load_local_env(path):
    if not os.path.exists(path):
        return

    with open(path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


load_local_env(os.path.join(ROOT, ".env"))

PORT = int(os.environ.get("PORT", "5173"))
APP_VERSION = os.environ.get("VERITAS_VERSION", "1.0.0")
SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "").rstrip("/")
SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN", "")
SPLUNK_AUTH_SCHEME = os.environ.get("SPLUNK_AUTH_SCHEME", "Bearer")
SPLUNK_VERIFY_SSL = os.environ.get("SPLUNK_VERIFY_SSL", "true").lower() not in {"0", "false", "no"}
SPLUNK_TIMEOUT = int(os.environ.get("SPLUNK_TIMEOUT", "8"))
SPLUNK_MAX_RESULTS = int(os.environ.get("SPLUNK_MAX_RESULTS", "25"))
SPLUNK_SEARCH_POLLS = int(os.environ.get("SPLUNK_SEARCH_POLLS", "20"))
SPLUNK_SEARCH_POLL_INTERVAL = float(os.environ.get("SPLUNK_SEARCH_POLL_INTERVAL", "0.5"))
SPLUNK_EARLIEST = os.environ.get("SPLUNK_EARLIEST", "-60m")
SPLUNK_LATEST = os.environ.get("SPLUNK_LATEST", "now")
VERITAS_SPLUNK_ROUTE = os.environ.get("VERITAS_SPLUNK_ROUTE", "mcp").lower()
VERITAS_SPLUNK_INDEX = os.environ.get("VERITAS_SPLUNK_INDEX", "veritas")
VERITAS_INCIDENT_ID = os.environ.get("VERITAS_INCIDENT_ID", "INC-001")
VERITAS_DISPLAY_INCIDENT_ID = os.environ.get("VERITAS_DISPLAY_INCIDENT_ID", "INC-2025-0001")
VERITAS_SOURCETYPE = os.environ.get("VERITAS_SOURCETYPE", "veritas:incident")
SPLUNK_MCP_SERVER = os.environ.get("SPLUNK_MCP_SERVER", os.path.join(ROOT, "splunk_mcp_server.py"))
SPLUNK_HEC_URL = os.environ.get("SPLUNK_HEC_URL", "").rstrip("/")
SPLUNK_HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "")
SPLUNK_HEC_VERIFY_SSL = os.environ.get("SPLUNK_HEC_VERIFY_SSL", os.environ.get("SPLUNK_VERIFY_SSL", "true")).lower() not in {"0", "false", "no"}
ONLINE_FEED_MANIFEST = os.environ.get("VERITAS_ONLINE_FEED_MANIFEST", DEFAULT_MANIFEST)
VERITAS_AUTH_TOKEN = os.environ.get("VERITAS_AUTH_TOKEN", "")
VERITAS_AUTH_USER = os.environ.get("VERITAS_AUTH_USER", "veritas")
VERITAS_ALLOWED_ORIGINS = {
    origin.strip()
    for origin in os.environ.get(
        "VERITAS_ALLOWED_ORIGINS",
        f"http://127.0.0.1:{PORT},http://localhost:{PORT}",
    ).split(",")
    if origin.strip()
}


ATTACK_EVENTS = [
    {
        "id": "SEC-3001",
        "time": "10:41:03",
        "source": "splunk:index=auth",
        "query": "index=auth user=admin@northstar.health action=login earliest=-30m | iplocation src_ip | transaction user maxspan=10m",
        "summary": "Impossible travel: admin account authenticated from Lagos and Frankfurt within three minutes.",
        "message": "Impossible travel: admin account authenticated from Lagos and Frankfurt within three minutes.",
        "event_type": "impossible_travel",
        "evidence_category": "identity",
        "user": "admin@northstar.health",
        "src_ip": "185.199.108.47",
        "geo": "Lagos, NG -> Frankfurt, DE",
        "action": "login",
        "severity": "high",
        "tags": ["auth", "impossible-travel", "identity"],
    },
    {
        "id": "SEC-3002",
        "time": "10:45:02",
        "source": "splunk:index=identity",
        "query": "index=identity user=admin@northstar.health action=mfa_challenge OR action=mfa_push | stats count by result src_ip",
        "summary": "MFA anomaly: push approved from unfamiliar ASN after two denied prompts.",
        "message": "MFA anomaly: push approved from unfamiliar ASN after two denied prompts.",
        "event_type": "mfa_anomaly",
        "evidence_category": "mfa",
        "user": "admin@northstar.health",
        "src_ip": "185.199.108.47",
        "geo": "Frankfurt, DE",
        "action": "mfa_push_approved",
        "severity": "high",
        "tags": ["mfa", "identity", "suspicious-asn"],
    },
    {
        "id": "SEC-3003",
        "time": "10:47:11",
        "source": "splunk:index=iam",
        "query": "index=iam user=admin@northstar.health action=role_grant role=super_admin | table _time user role actor src_ip",
        "summary": "Privilege escalation: admin account granted itself super_admin role from the suspicious session.",
        "message": "Privilege escalation: admin account granted itself super_admin role from the suspicious session.",
        "event_type": "privilege_escalation",
        "evidence_category": "iam",
        "user": "admin@northstar.health",
        "src_ip": "185.199.108.47",
        "geo": "Frankfurt, DE",
        "action": "role_grant",
        "severity": "critical",
        "tags": ["iam", "privilege-escalation"],
    },
    {
        "id": "SEC-3004",
        "time": "10:48:27",
        "source": "splunk:index=api_gateway",
        "query": "index=api_gateway user=admin@northstar.health endpoint=/api/admin/export status=200 | stats count sum(bytes) by user src_ip",
        "summary": "Admin API access: privileged export endpoint returned 200 to the suspicious session.",
        "message": "Admin API access: privileged export endpoint returned 200 to the suspicious session.",
        "event_type": "admin_api_access",
        "evidence_category": "api",
        "user": "admin@northstar.health",
        "src_ip": "185.199.108.47",
        "geo": "Frankfurt, DE",
        "action": "admin_api_export",
        "severity": "critical",
        "tags": ["api", "admin-api", "sensitive-export"],
    },
    {
        "id": "SEC-3005",
        "time": "10:50:09",
        "source": "splunk:index=edr",
        "query": "index=edr user=admin@northstar.health process=curl OR process=python | table _time host process command_line",
        "summary": "Scripted download: EDR observed curl/python tooling on the admin workstation session.",
        "message": "Scripted download: EDR observed curl/python tooling on the admin workstation session.",
        "event_type": "scripted_download",
        "evidence_category": "endpoint",
        "user": "admin@northstar.health",
        "src_ip": "185.199.108.47",
        "geo": "Frankfurt, DE",
        "action": "download",
        "severity": "high",
        "tags": ["edr", "automation", "exfiltration"],
    },
    {
        "id": "SEC-3006",
        "time": "10:51:22",
        "source": "splunk:index=object_storage",
        "query": "index=object_storage user=admin@northstar.health action=cloud_export bucket=case-exports | table _time user bucket object bytes status",
        "summary": "Cloud export: sensitive case archive was written to object storage from the suspicious session.",
        "message": "Cloud export: sensitive case archive was written to object storage from the suspicious session.",
        "event_type": "cloud_export",
        "evidence_category": "cloud_storage",
        "user": "admin@northstar.health",
        "src_ip": "185.199.108.47",
        "geo": "Frankfurt, DE",
        "action": "cloud_export",
        "severity": "critical",
        "tags": ["cloud", "object-storage", "data-exfiltration"],
    },
]

INCIDENT_PROFILES = [
    {
        "id": "admin-takeover",
        "title": "ADMIN ACCOUNT TAKEOVER",
        "display_incident_id": VERITAS_DISPLAY_INCIDENT_ID,
        "summary": "Impossible travel, MFA anomaly, privilege escalation, admin API access, scripted download, and cloud export.",
        "event_ids": ["SEC-3001", "SEC-3002", "SEC-3003", "SEC-3004", "SEC-3005", "SEC-3006"],
        "recommended_policy": "standard",
    },
    {
        "id": "cloud-key-abuse",
        "title": "CLOUD API KEY ABUSE",
        "display_incident_id": "INC-2025-0002",
        "summary": "Suspicious identity activity and sensitive cloud export with incomplete DLP telemetry.",
        "event_ids": ["SEC-3001", "SEC-3004", "SEC-3006"],
        "recommended_policy": "strict",
    },
    {
        "id": "ransomware-containment",
        "title": "RANSOMWARE CONTAINMENT DRILL",
        "display_incident_id": "INC-2025-0003",
        "summary": "Identity anomaly plus endpoint automation where fast containment may be necessary.",
        "event_ids": ["SEC-3001", "SEC-3002", "SEC-3005"],
        "recommended_policy": "emergency",
    },
]


POLICY_PROFILES = {
    "standard": {
        "label": "Standard",
        "description": "Balanced response governance for normal incident response.",
        "score_adjustment": 0,
        "approved_to_caution": False,
    },
    "strict": {
        "label": "Strict",
        "description": "Raises scrutiny for legal, compliance, and business-impact decisions.",
        "score_adjustment": -8,
        "approved_to_caution": True,
    },
    "emergency": {
        "label": "Emergency",
        "description": "Allows fast reversible containment while still blocking unsafe declarations.",
        "score_adjustment": 6,
        "approved_to_caution": False,
    },
}


DETECTION_RULES = [
    {
        "id": "DET-4101",
        "name": "Impossible travel admin login",
        "severity": "High",
        "confidence": 92,
        "requires": ["SEC-3001"],
        "risk": 24,
        "finding": "The same admin account authenticated from Lagos and Frankfurt within three minutes.",
        "response": "Revoke the suspicious session and force credential reset.",
    },
    {
        "id": "DET-4102",
        "name": "MFA anomaly followed by approval",
        "severity": "High",
        "confidence": 84,
        "requires": ["SEC-3002"],
        "risk": 18,
        "finding": "MFA was denied twice, then approved from an unfamiliar ASN.",
        "response": "Disable push approval for the account and require step-up verification.",
    },
    {
        "id": "DET-4103",
        "name": "Privilege escalation from suspicious session",
        "severity": "Critical",
        "confidence": 95,
        "requires": ["SEC-3003"],
        "risk": 28,
        "finding": "The suspicious admin session granted itself super_admin privileges.",
        "response": "Disable the account and remove the unauthorized role grant.",
    },
    {
        "id": "DET-4104",
        "name": "Admin API access with cloud export",
        "severity": "Critical",
        "confidence": 89,
        "requires": ["SEC-3004", "SEC-3005", "SEC-3006"],
        "risk": 30,
        "finding": "The suspicious session accessed admin export APIs, scripted download tooling appeared, and a cloud export was written.",
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

ACTION_DECISION_MAP = {
    "revoke-token": "revoke-session",
    "disable-account": "disable-admin",
    "block-ip": "block-source-ip",
    "open-incident": None,
}

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
                "evidence": ["SEC-3001"],
                "mandatory": True,
                "spl": "index=auth user=admin@northstar.health action=login earliest=-30m | iplocation src_ip | table _time user src_ip geo result",
            },
            {
                "id": "mfa-anomaly",
                "label": "MFA anomaly",
                "evidence": ["SEC-3002"],
                "mandatory": True,
                "spl": "index=identity user=admin@northstar.health action=mfa_challenge OR action=mfa_push | stats count by result src_ip",
            },
            {
                "id": "active-session-risk",
                "label": "Active risky session",
                "evidence": ["SEC-3001", "SEC-3004"],
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
                "evidence": ["SEC-3001"],
                "mandatory": True,
                "spl": "index=auth user=admin@northstar.health action=login earliest=-30m | iplocation src_ip | table _time user src_ip geo result",
            },
            {
                "id": "mfa-anomaly",
                "label": "MFA anomaly",
                "evidence": ["SEC-3002"],
                "mandatory": True,
                "spl": "index=identity user=admin@northstar.health action=mfa_challenge OR action=mfa_push | stats count by result src_ip",
            },
            {
                "id": "privilege-escalation",
                "label": "Privilege escalation",
                "evidence": ["SEC-3003"],
                "mandatory": True,
                "spl": "index=iam user=admin@northstar.health action=role_grant role=super_admin | table _time user role actor src_ip",
            },
            {
                "id": "abnormal-api",
                "label": "Abnormal sensitive API access",
                "evidence": ["SEC-3004"],
                "mandatory": False,
                "spl": "index=api_gateway user=admin@northstar.health endpoint=/api/admin/export | stats count sum(bytes) by user src_ip status",
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
                "evidence": ["SEC-3001"],
                "mandatory": True,
                "spl": "index=auth src_ip=185.199.108.47 | stats count by user action result",
            },
            {
                "id": "sensitive-access",
                "label": "Sensitive endpoint access",
                "evidence": ["SEC-3004"],
                "mandatory": True,
                "spl": "index=api_gateway src_ip=185.199.108.47 endpoint=/api/admin/export | stats count sum(bytes) by status",
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
                "evidence": ["SEC-3004"],
                "mandatory": True,
                "negative": True,
                "spl": "index=api_gateway user=admin@northstar.health endpoint=/api/admin/export | stats count sum(bytes) by user src_ip status",
            },
            {
                "id": "export-events",
                "label": "Export/download events checked",
                "evidence": ["SEC-3005"],
                "mandatory": True,
                "negative": True,
                "spl": "index=veritas incident_id=INC-001 action=export OR action=download | stats count by user, src_ip, object, status",
            },
            {
                "id": "object-storage",
                "label": "Object storage access checked",
                "evidence": ["SEC-3006"],
                "mandatory": True,
                "negative": True,
                "spl": "index=veritas incident_id=INC-001 sourcetype=object_storage | stats count by user, bucket, object, action, status",
            },
            {
                "id": "exfil-indicators",
                "label": "Exfiltration indicators checked",
                "evidence": ["SEC-3005"],
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
    "incident_key": "admin-takeover",
    "policy_profile": "standard",
    "events": [],
    "detections": [],
    "actions": [],
    "approvals": {},
    "last_splunk_load": None,
    "last_online_feed": None,
    "last_investigation": None,
    "custom_request": None,
}


def case_summary():
    request_info = LAB_STATE.get("custom_request") or {}
    feedback = request_info.get("feedback") or {}
    last_load = LAB_STATE.get("last_splunk_load") or {}
    last_feed = LAB_STATE.get("last_online_feed") or {}
    decisions = evaluate_decisions()
    ready_count = len([item for item in decisions if item["status"] in {"Approved", "Caution"}])
    blocked_count = len([item for item in decisions if item["status"] in {"Blocked", "Not Ready"}])
    title = request_info.get("title") or incident_profile().get("title") or "Veritas case"
    source = "Analyst Evidence" if request_info else "Splunk Evidence" if last_load else "Online Feed" if last_feed else "No Evidence"
    outcome = feedback.get("message") or (
        f"{last_load.get('mapped_events', 0)} indexed event(s) loaded"
        if last_load
        else f"{len(last_feed.get('ingested') or [])} HEC event(s) ingested"
        if last_feed
        else "No run yet"
    )
    return {
        "id": datetime.now(timezone.utc).strftime("CASE-%Y%m%d%H%M%S"),
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "title": title,
        "source": source,
        "stage": LAB_STATE.get("stage"),
        "events": len(LAB_STATE.get("events") or []),
        "ready_decisions": ready_count,
        "blocked_decisions": blocked_count,
        "action": request_info.get("action_label"),
        "outcome": outcome,
        "executed": bool(feedback.get("executed")),
    }


def read_case_history():
    if not os.path.exists(CASE_HISTORY_PATH):
        return []
    try:
        with open(CASE_HISTORY_PATH, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload if isinstance(payload, list) else []
    except (OSError, json.JSONDecodeError, TypeError):
        return []


def append_case_history(summary):
    history = read_case_history()
    history = [item for item in history if item.get("title") != summary.get("title") or item.get("outcome") != summary.get("outcome")]
    history.insert(0, summary)
    with open(CASE_HISTORY_PATH, "w", encoding="utf-8") as handle:
        json.dump(history[:12], handle, indent=2)


def save_last_run(add_history=False):
    payload = {
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "lab_state": LAB_STATE,
    }
    with open(LAST_RUN_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    if add_history:
        append_case_history(case_summary())


def restore_last_run():
    if not os.path.exists(LAST_RUN_PATH):
        return
    try:
        with open(LAST_RUN_PATH, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        saved_state = payload.get("lab_state")
        if isinstance(saved_state, dict):
            for key in LAB_STATE:
                if key in saved_state:
                    LAB_STATE[key] = saved_state[key]
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return


def clear_saved_run():
    try:
        os.remove(LAST_RUN_PATH)
    except FileNotFoundError:
        return


restore_last_run()


CUSTOM_SIGNAL_MAP = [
    ("SEC-3001", ("impossible travel", "new country", "new location", "unusual location", "foreign", "geo", "login")),
    ("SEC-3002", ("mfa", "push", "fatigue", "approval", "denied")),
    ("SEC-3003", ("privilege", "super_admin", "domain admin", "role grant", "escalation")),
    ("SEC-3004", ("admin api", "api", "sensitive data", "export endpoint")),
    ("SEC-3005", ("script", "curl", "python", "download", "edr", "workstation")),
    ("SEC-3006", ("cloud export", "object storage", "bucket", "archive", "exfiltration")),
]


def action_status():
    completed = {action["id"] for action in LAB_STATE["actions"]}
    return [
        {
            **action,
            "decision_id": ACTION_DECISION_MAP.get(action["id"]),
            "approval": LAB_STATE["approvals"].get(ACTION_DECISION_MAP.get(action["id"]), "pending")
            if ACTION_DECISION_MAP.get(action["id"])
            else "not-required",
            "status": "completed" if action["id"] in completed else "pending",
        }
        for action in RESPONSE_ACTIONS
    ]


def incident_profile(profile_id=None):
    key = profile_id or LAB_STATE.get("incident_key") or "admin-takeover"
    return next((profile for profile in INCIDENT_PROFILES if profile["id"] == key), INCIDENT_PROFILES[0])


def active_attack_events():
    wanted = set(incident_profile()["event_ids"])
    return [event for event in ATTACK_EVENTS if event["id"] in wanted]


def policy_profile(profile_id=None):
    key = profile_id or LAB_STATE.get("policy_profile") or "standard"
    return POLICY_PROFILES.get(key, POLICY_PROFILES["standard"])


def completed_action_ids():
    return {action["id"] for action in LAB_STATE["actions"]}


def clear_lab_state(stage="idle"):
    LAB_STATE["stage"] = stage
    LAB_STATE["events"] = []
    LAB_STATE["detections"] = []
    LAB_STATE["actions"] = []
    LAB_STATE["approvals"] = {}
    LAB_STATE["last_splunk_load"] = None
    LAB_STATE["last_online_feed"] = None
    LAB_STATE["last_investigation"] = None
    LAB_STATE["custom_request"] = None
    clear_saved_run()


def select_incident(profile_id, load=False):
    if not any(profile["id"] == profile_id for profile in INCIDENT_PROFILES):
        return {"ok": False, "error": "Unknown incident profile"}
    LAB_STATE["incident_key"] = profile_id
    LAB_STATE["policy_profile"] = incident_profile(profile_id).get("recommended_policy", "standard")
    clear_lab_state("idle")
    if load:
        LAB_STATE["events"] = active_attack_events()
        LAB_STATE["stage"] = "attack-complete"
        run_detections()
    return {"ok": True, **state_payload()}


def set_policy_profile(profile_id):
    if profile_id not in POLICY_PROFILES:
        return {"ok": False, "error": "Unknown policy profile"}
    LAB_STATE["policy_profile"] = profile_id
    return {"ok": True, **state_payload()}


def decision_lookup():
    return {decision["id"]: decision for decision in evaluate_decisions()}


def eligible_for_approval(decision):
    return decision and decision["status"] in {"Approved", "Caution"}


def approval_payload():
    decisions = decision_lookup()
    return [
        {
            "action_id": action["id"],
            "action_label": action["label"],
            "decision_id": ACTION_DECISION_MAP.get(action["id"]),
            "decision_title": decisions.get(ACTION_DECISION_MAP.get(action["id"]), {}).get("title"),
            "decision_status": decisions.get(ACTION_DECISION_MAP.get(action["id"]), {}).get("status"),
            "readiness": decisions.get(ACTION_DECISION_MAP.get(action["id"]), {}).get("readiness"),
            "approval": LAB_STATE["approvals"].get(ACTION_DECISION_MAP.get(action["id"]), "pending")
            if ACTION_DECISION_MAP.get(action["id"])
            else "not-required",
            "executed": action["id"] in completed_action_ids(),
            "eligible": eligible_for_approval(decisions.get(ACTION_DECISION_MAP.get(action["id"]))),
            "summary": action["summary"],
        }
        for action in RESPONSE_ACTIONS
        if ACTION_DECISION_MAP.get(action["id"])
    ]


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
        "origin": splunk_status()["search_provider"],
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

    active_policy = policy_profile()
    if active_policy["score_adjustment"]:
        score = max(0, min(100, score + active_policy["score_adjustment"]))
    if active_policy["approved_to_caution"] and status == "Approved" and policy["human_approval"]:
        status = "Caution"
    if LAB_STATE.get("policy_profile") == "emergency" and policy["id"] == "revoke-session" and not contradicted and score >= 67:
        status = "Approved"
        score = max(score, 84)
    if policy["id"] == "declare-no-data-access" and status != "Blocked":
        status = "Blocked"
        score = min(score, 38)

    reason = {
        "Approved": "Evidence threshold is met for this response decision.",
        "Caution": "Most evidence is present, but blast radius or residual uncertainty requires human review.",
        "Blocked": "This decision is unsafe because evidence contradicts it or mandatory evidence is missing.",
        "Not Ready": "Not enough required evidence has been collected yet.",
    }[status]
    if LAB_STATE.get("policy_profile") == "strict" and status == "Caution":
        reason = f"{reason} Strict policy mode requires extra analyst scrutiny."
    if LAB_STATE.get("policy_profile") == "emergency" and policy["id"] == "revoke-session":
        reason = f"{reason} Emergency policy mode favors reversible session containment."

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
        "policy_profile": LAB_STATE.get("policy_profile", "standard"),
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


def custom_event_ids(text):
    lowered = text.lower()
    ids = []
    for event_id, keywords in CUSTOM_SIGNAL_MAP:
        if any(keyword in lowered for keyword in keywords):
            ids.append(event_id)

    if "SEC-3002" in ids and "SEC-3001" not in ids:
        ids.insert(0, "SEC-3001")
    if "SEC-3006" in ids and "SEC-3004" not in ids and any(word in lowered for word in ("export", "data", "cloud")):
        ids.insert(ids.index("SEC-3006"), "SEC-3004")
    if not ids:
        ids.append("SEC-3001")

    ordered = []
    for event in ATTACK_EVENTS:
        if event["id"] in ids and event["id"] not in ordered:
            ordered.append(event["id"])
    return ordered


def custom_signal_details(event_ids):
    details = []
    for event_id in event_ids:
        prototype = event_prototype(event_id)
        if prototype:
            details.append(
                {
                    "id": event_id,
                    "title": prototype["summary"],
                    "source": prototype["source"],
                    "severity": prototype["severity"],
                }
            )
    return details


def custom_events_from_text(text):
    selected_ids = custom_event_ids(text)
    events = []
    for index, event_id in enumerate(selected_ids, start=1):
        prototype = event_prototype(event_id)
        if not prototype:
            continue
        events.append(
            {
                **prototype,
                "time": f"custom+{index:02d}",
                "summary": prototype["summary"],
                "origin": "analyst-evidence",
                "evidence_source": "Analyst-supplied evidence",
            }
        )
    return events


def custom_decision_feedback(action, decision, executed, message):
    missing = []
    status = "not-required"
    readiness = None
    decision_title = None
    if decision:
        status = decision["status"]
        readiness = decision["readiness"]
        decision_title = decision["title"]
        missing = [
            {
                "id": item["id"],
                "label": item["label"],
                "status": item["status"],
                "mandatory": item["mandatory"],
                "spl": item["spl"],
            }
            for item in decision["missing_evidence"]
        ]

    if executed:
        next_step = "Action executed. Preserve the evidence timeline and export the decision audit brief."
    elif missing:
        next_step = "Action held. Collect the missing evidence and rerun this request."
    else:
        next_step = "Action held. Review the decision status before execution."

    return {
        "action_id": action["id"],
        "action_label": action["label"],
        "decision_title": decision_title,
        "decision_status": status,
        "readiness": readiness,
        "executed": executed,
        "message": message,
        "missing_evidence": missing,
        "next_step": next_step,
    }


def run_custom_request(payload):
    title = (payload.get("title") or "Custom incident request").strip()[:120]
    evidence_text = (payload.get("evidence") or payload.get("text") or "").strip()
    action_id = payload.get("action") or payload.get("action_id") or "revoke-token"
    execute = bool(payload.get("execute", True))

    action = next((item for item in RESPONSE_ACTIONS if item["id"] == action_id), None)
    if action is None:
        return {"ok": False, "error": "Unknown response action"}
    if not evidence_text:
        return {"ok": False, "error": "Evidence text is required"}

    selected_event_ids = custom_event_ids(evidence_text)
    clear_lab_state("custom-request")
    LAB_STATE["events"] = custom_events_from_text(evidence_text)
    run_detections()
    LAB_STATE["custom_request"] = {
        "title": title,
        "evidence": evidence_text,
        "action_id": action_id,
        "action_label": action["label"],
        "execute_requested": execute,
        "matched_signals": custom_signal_details(selected_event_ids),
    }

    decisions = decision_lookup()
    decision_id = ACTION_DECISION_MAP.get(action_id)
    decision = decisions.get(decision_id) if decision_id else None
    executed = False
    message = "Evidence loaded and indicators recalculated."

    if action_id == "open-incident":
        LAB_STATE["actions"].append(action)
        LAB_STATE["stage"] = "responding"
        executed = True
        message = "Incident brief opened from custom request."
    elif execute and decision and eligible_for_approval(decision):
        LAB_STATE["approvals"][decision_id] = "approved"
        LAB_STATE["actions"].append(action)
        LAB_STATE["stage"] = "contained" if calculate_risk() <= 35 else "responding"
        executed = True
        message = f"{action['label']} executed because the evidence threshold was met."
    elif execute and decision:
        message = f"{action['label']} was not executed because decision status is {decision['status']}."
    elif not execute:
        message = "Evidence loaded. Execution was not requested."

    LAB_STATE["custom_request"]["executed"] = executed
    LAB_STATE["custom_request"]["message"] = message
    LAB_STATE["custom_request"]["feedback"] = custom_decision_feedback(action, decision, executed, message)
    save_last_run(add_history=True)
    return {"ok": True, "message": message, **state_payload()}


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


def splunk_hec_configured():
    return bool(SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN)


def splunk_mcp_enabled():
    return splunk_configured() and VERITAS_SPLUNK_ROUTE == "mcp"


def splunk_status():
    configured_provider = "splunk-mcp" if splunk_mcp_enabled() else "splunk-rest" if splunk_configured() else "mock-mcp"
    last_load = LAB_STATE.get("last_splunk_load") or {}
    return {
        "provider": configured_provider,
        "search_provider": last_load.get("provider") or configured_provider,
        "configured": splunk_configured(),
        "hec_configured": splunk_hec_configured(),
        "route": VERITAS_SPLUNK_ROUTE if splunk_configured() else "mock",
        "mcp_routed": splunk_mcp_enabled(),
        "host": SPLUNK_HOST or None,
        "index": VERITAS_SPLUNK_INDEX,
        "incident_id": VERITAS_INCIDENT_ID,
        "display_incident_id": VERITAS_DISPLAY_INCIDENT_ID,
        "sourcetype": VERITAS_SOURCETYPE,
        "auth_scheme": SPLUNK_AUTH_SCHEME if SPLUNK_TOKEN else None,
        "verify_ssl": SPLUNK_VERIFY_SSL,
        "max_results": SPLUNK_MAX_RESULTS,
        "search_polls": SPLUNK_SEARCH_POLLS,
        "earliest": SPLUNK_EARLIEST,
        "latest": SPLUNK_LATEST,
        "last_load": LAB_STATE.get("last_splunk_load"),
        "last_online_feed": LAB_STATE.get("last_online_feed"),
    }


def splunk_context():
    if SPLUNK_VERIFY_SSL:
        return None
    return ssl._create_unverified_context()


def splunk_hec_context():
    if SPLUNK_HEC_VERIFY_SSL:
        return None
    return ssl._create_unverified_context()


def normalize_hec_url(hec_url):
    cleaned = hec_url.rstrip("/")
    if cleaned.endswith("/services/collector"):
        return f"{cleaned}/event"
    return cleaned


def send_hec_payload(payload):
    if not splunk_hec_configured():
        raise RuntimeError("Splunk HEC is not configured. Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN, then restart the server.")

    req = request.Request(
        normalize_hec_url(SPLUNK_HEC_URL),
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
            "Content-Type": "application/json",
        },
    )
    with request.urlopen(req, timeout=SPLUNK_TIMEOUT, context=splunk_hec_context()) as response:
        return json.loads(response.read().decode("utf-8"))


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
    for _ in range(SPLUNK_SEARCH_POLLS):
        status = splunk_request(
            f"/services/search/jobs/{quoted_sid}",
            {"output_mode": "json"},
        )
        entry = (status.get("entry") or [{}])[0]
        content = entry.get("content", {})
        dispatch_state = content.get("dispatchState", dispatch_state)
        if content.get("isDone") or dispatch_state == "DONE":
            break
        time.sleep(SPLUNK_SEARCH_POLL_INTERVAL)

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


def read_mcp_message(proc):
    line = proc.stdout.readline()
    if not line:
        stderr = proc.stderr.read() if proc.stderr else ""
        raise RuntimeError(f"Splunk MCP server exited before responding. {stderr.strip()}")
    return json.loads(line)


def write_mcp_message(proc, message):
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()


def call_splunk_mcp_tool(tool_name, arguments=None):
    if not splunk_configured():
        raise RuntimeError("Splunk MCP route requires SPLUNK_HOST and SPLUNK_TOKEN.")
    if not os.path.exists(SPLUNK_MCP_SERVER):
        raise RuntimeError(f"Splunk MCP server entry point not found: {SPLUNK_MCP_SERVER}")

    proc = subprocess.Popen(
        [sys.executable, SPLUNK_MCP_SERVER],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        write_mcp_message(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "veritas-dashboard", "version": APP_VERSION},
                },
            },
        )
        init_response = read_mcp_message(proc)
        if "error" in init_response:
            raise RuntimeError(init_response["error"].get("message", "MCP initialize failed"))

        write_mcp_message(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        write_mcp_message(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments or {}},
            },
        )
        tool_response = read_mcp_message(proc)
        if "error" in tool_response:
            raise RuntimeError(tool_response["error"].get("message", "MCP tool call failed"))
        result = tool_response.get("result", {})
        if result.get("isError"):
            structured = result.get("structuredContent") or {}
            raise RuntimeError(structured.get("error") or json.dumps(structured))
        return result.get("structuredContent") or {}
    finally:
        try:
            if proc.stdin:
                proc.stdin.close()
        except OSError:
            pass
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()


def splunk_mcp_search(query, earliest=SPLUNK_EARLIEST, latest=SPLUNK_LATEST, count=None):
    return call_splunk_mcp_tool(
        "splunk.search",
        {
            "query": query,
            "earliest": earliest,
            "latest": latest,
            "count": count or SPLUNK_MAX_RESULTS,
        },
    )


def splunk_mcp_veritas_evidence(count=None):
    return call_splunk_mcp_tool(
        "splunk.veritas_evidence",
        {
            "incident_id": VERITAS_INCIDENT_ID,
            "index": VERITAS_SPLUNK_INDEX,
            "sourcetype": VERITAS_SOURCETYPE,
            "earliest": SPLUNK_EARLIEST,
            "latest": SPLUNK_LATEST,
            "count": count or SPLUNK_MAX_RESULTS,
        },
    )


def search_job_id(detection_id, index):
    return f"sid_veritas_{detection_id.lower()}_{index:03d}"


def dashboard_tool_envelope(tool, arguments, result):
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
        result = splunk_mcp_search(query) if splunk_mcp_enabled() else splunk_search(query)
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


def fetch_online_feed_events():
    manifest = read_json(ONLINE_FEED_MANIFEST)
    events, fetched = normalize_sources(manifest)
    return manifest, events, fetched


def ingest_online_feed(load_after=True):
    if not splunk_hec_configured():
        return {
            "ok": False,
            "error": "Splunk HEC is not configured. Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN, then restart the server.",
            "integration": splunk_status(),
        }

    manifest, events, fetched = fetch_online_feed_events()
    args = SimpleNamespace(
        incident_id=VERITAS_INCIDENT_ID,
        display_incident_id=VERITAS_DISPLAY_INCIDENT_ID,
        index=VERITAS_SPLUNK_INDEX,
        sourcetype=VERITAS_SOURCETYPE,
    )
    payloads = build_payloads(events, args)
    ingested = []
    failures = []

    for payload in payloads:
        event_id = payload["event"]["event_id"]
        try:
            result = send_hec_payload(payload)
        except Exception as error:
            failures.append({"event_id": event_id, "error": str(error)})
            continue
        if result.get("code") == 0:
            ingested.append(event_id)
        else:
            failures.append({"event_id": event_id, "error": json.dumps(result)})

    LAB_STATE["last_online_feed"] = {
        "provider": "splunk-attack-data-online",
        "upstream": manifest.get("upstream", {}),
        "sources_fetched": fetched,
        "events_ready": [event["id"] for event in events],
        "ingested": ingested,
        "failures": failures,
        "hec_configured": splunk_hec_configured(),
        "index": VERITAS_SPLUNK_INDEX,
        "sourcetype": VERITAS_SOURCETYPE,
        "incident_id": VERITAS_INCIDENT_ID,
    }

    if failures:
        return {
            "ok": False,
            "error": f"Online feed HEC ingestion failed for {len(failures)} of {len(payloads)} events.",
            "feed": LAB_STATE["last_online_feed"],
            "integration": splunk_status(),
        }

    LAB_STATE["stage"] = "online-feed-ingested"
    LAB_STATE["events"] = []
    LAB_STATE["detections"] = []
    LAB_STATE["actions"] = []
    LAB_STATE["approvals"] = {}
    LAB_STATE["custom_request"] = None
    LAB_STATE["last_investigation"] = None
    LAB_STATE["last_splunk_load"] = None

    if not load_after:
        save_last_run(add_history=True)
        return {
            "ok": True,
            **state_payload(),
            "feed": LAB_STATE["last_online_feed"],
        }

    # Give Splunk a short moment to make the HEC writes searchable.
    time.sleep(float(os.environ.get("VERITAS_POST_HEC_WAIT", "1.5")))
    load_result = load_splunk_evidence()
    if load_result.get("ok"):
        load_result["feed"] = LAB_STATE["last_online_feed"]
        save_last_run(add_history=True)
        return load_result

    save_last_run(add_history=True)
    return {
        "ok": True,
        **state_payload(),
        "feed": LAB_STATE["last_online_feed"],
        "search_warning": load_result.get("error"),
        "search": load_result.get("search"),
    }


def load_splunk_evidence():
    if not splunk_configured():
        return {
            "ok": False,
            "error": "Splunk is not configured. Set SPLUNK_HOST and SPLUNK_TOKEN, then restart the server.",
        }

    event_ids = [event["id"] for event in active_attack_events()]
    query = veritas_event_search(event_ids)
    try:
        search_result = (
            splunk_mcp_veritas_evidence(count=max(len(event_ids), SPLUNK_MAX_RESULTS))
            if splunk_mcp_enabled()
            else splunk_search(
                query,
                earliest=SPLUNK_EARLIEST,
                latest=SPLUNK_LATEST,
                count=max(len(event_ids), SPLUNK_MAX_RESULTS),
            )
        )
    except Exception as error:
        LAB_STATE["last_splunk_load"] = {
            "query": query,
            "provider": "splunk-mcp" if splunk_mcp_enabled() else "splunk-rest",
            "error": str(error),
            "mcp_routed": splunk_mcp_enabled(),
        }
        return {
            "ok": False,
            "error": f"Splunk {'MCP' if splunk_mcp_enabled() else 'REST'} search failed. Verify {SPLUNK_HOST or 'SPLUNK_HOST'}, credentials, SSL settings, and indexed Veritas events.",
            "search": LAB_STATE["last_splunk_load"],
        }
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
    LAB_STATE["approvals"] = {}
    LAB_STATE["custom_request"] = None
    LAB_STATE["last_investigation"] = None
    LAB_STATE["last_splunk_load"] = {
        "query": query,
        "job_id": search_result["job_id"],
        "provider": search_result["provider"],
        "result_count": search_result["result_count"],
        "mapped_events": len(ordered_events),
        "missing_events": [event_id for event_id in event_ids if event_id not in events_by_id],
        "link": search_result["link"],
        "dispatch_state": search_result.get("dispatch_state"),
        "mcp_routed": splunk_mcp_enabled(),
        "route": VERITAS_SPLUNK_ROUTE if splunk_configured() else "mock",
    }
    save_last_run(add_history=True)

    return {
        "ok": True,
        **state_payload(),
        "search": LAB_STATE["last_splunk_load"],
    }


def state_payload():
    integration = splunk_status()
    if LAB_STATE.get("custom_request"):
        integration = {
            **integration,
            "provider": "custom-input",
            "search_provider": "custom-input",
            "request": LAB_STATE["custom_request"],
        }
    decisions = evaluate_decisions()
    return {
        "incident": incident_profile(),
        "policy": {"id": LAB_STATE.get("policy_profile", "standard"), **policy_profile()},
        "incident_catalog": INCIDENT_PROFILES,
        "policy_catalog": [
            {"id": profile_id, **profile}
            for profile_id, profile in POLICY_PROFILES.items()
        ],
        "stage": LAB_STATE["stage"],
        "events": LAB_STATE["events"],
        "detections": LAB_STATE["detections"],
        "decisions": decisions,
        "readiness_strip": [
            {
                "id": decision["id"],
                "title": decision["title"],
                "readiness": decision["readiness"],
                "status": decision["status"],
            }
            for decision in decisions
        ],
        "integrity": evidence_integrity(),
        "actions": action_status(),
        "approvals": approval_payload(),
        "risk": calculate_risk(),
        "integration": integration,
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
            dashboard_tool_envelope(
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
            dashboard_tool_envelope(
                "veritas.demo_notable_event",
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
        dashboard_tool_envelope(
            "veritas.demo_risk_score",
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
    decision_detail_lines = []
    for decision in decisions:
        found_labels = ", ".join(item["label"] for item in decision["found_evidence"]) or "none"
        missing_labels = ", ".join(item["label"] for item in decision["missing_evidence"]) or "none"
        approval_requirement = "Human approval required" if decision["human_approval"] else "No human approval required"
        decision_detail_lines.extend(
            [
                f"- Proposed decision: {decision['title']}",
                f"  Readiness score: {decision['readiness']}%",
                f"  Status: {decision['status']}",
                f"  Evidence found: {found_labels}",
                f"  Evidence missing: {missing_labels}",
                f"  Blast radius: {decision['blast_radius']}",
                f"  Recommended next action: {decision['recommended_action']}",
                f"  Human approval requirement: {approval_requirement}",
            ]
        )
    missing_lines = "\n".join(
        f"- {decision['title']}: {check['label']} -> {check['spl']}"
        for decision in decisions
        for check in decision["missing_evidence"]
    )
    action_lines = "\n".join(
        f"- {item['label']}: {item['summary']}" for item in LAB_STATE["actions"]
    )
    approval_lines = line_or_default(
        [
            f"- {item['decision_title']}: approval={item['approval']}, action={item['action_label']}, readiness={item['readiness']}%, executed={'yes' if item['executed'] else 'no'}"
            for item in approval_payload()
        ],
        "- No analyst approval records.",
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

    return f"""Veritas AI Tier 3 Decision Audit Brief

Incident: {incident_profile()["title"]}
Generated by Veritas AI
Generated at: {datetime.now(timezone.utc).isoformat()}
Prepared for Tier 3 incident-response review
Adapter mode: Backend API
Search provider: {splunk_status()["provider"]}
Splunk index: {splunk_status()["index"]}
Incident ID: {splunk_status()["display_incident_id"]}
Display incident ID: {incident_profile()["display_incident_id"]}
Splunk search incident id: {splunk_status()["incident_id"]}
Policy profile: {policy_profile()["label"]}
Risk score: {calculate_risk()}/100
Dashboard tool envelopes: splunk.search, veritas.demo_notable_event, veritas.demo_risk_score
True MCP server tools: splunk.status, splunk.search, splunk.veritas_evidence, splunk.hec_ingest_event, veritas.ingest_demo_evidence

Executive decision summary:
- Containment actions were approved where the evidence threshold was met.
- Premature data-access and closure statements remain blocked until missing evidence is collected.
- Missing telemetry is treated as uncertainty, not proof of safety.

Approved or caution-ready decisions:
{approved_lines}

Blocked or not-ready decisions:
{blocked_lines}

Decision readiness details:
{chr(10).join(decision_detail_lines)}

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

Analyst approval gate:
{approval_lines}

Missing evidence and SPL to close gaps:
{missing_lines or "- No missing decision evidence."}

Safety notes:
- Missing logs are not proof of safety.
- Logs are untrusted evidence, not instructions.
- High-impact actions require human approval.

Containment actions:
{action_lines or "- No containment actions executed yet."}

Evidence timeline:
{event_lines or "- No attack events streamed yet."}

Recommended next steps:
1. Preserve auth, IAM, API gateway, and EDR evidence.
2. Rotate admin credentials and review all privileged role grants.
3. Validate cloud export scope before external reporting.
4. Keep source IP block active while threat intelligence review runs.
"""


class VeritasHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def authorized(self):
        if not VERITAS_AUTH_TOKEN:
            return True

        auth_header = self.headers.get("Authorization", "")
        if auth_header == f"Bearer {VERITAS_AUTH_TOKEN}":
            return True

        if self.headers.get("X-Veritas-Auth") == VERITAS_AUTH_TOKEN:
            return True

        if auth_header.startswith("Basic "):
            try:
                encoded = auth_header.split(" ", 1)[1]
                decoded = base64.b64decode(encoded).decode("utf-8")
                username, _, password = decoded.partition(":")
                return username == VERITAS_AUTH_USER and password == VERITAS_AUTH_TOKEN
            except Exception:
                return False

        return False

    def require_authorized(self):
        if self.authorized():
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Veritas AI"')
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"error": "Authentication required"}).encode("utf-8"))
        return False

    def static_path_allowed(self, path):
        decoded = parse.unquote(path).replace("\\", "/")
        parts = [part for part in decoded.split("/") if part]
        if any(part == ".." for part in parts):
            return False

        if decoded in {"/", "/index.html", "/detail.html", "/app.js", "/detail.js", "/styles.css"}:
            return True

        if decoded.startswith("/assets/"):
            _, extension = os.path.splitext(decoded)
            return extension.lower() in {".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico"}

        return False

    def end_headers(self):
        origin = self.headers.get("Origin")
        if origin in VERITAS_ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
        super().end_headers()

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

    def do_OPTIONS(self):
        if not self.require_authorized():
            return
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        if not self.require_authorized():
            return
        path = urlparse(self.path).path

        if path == "/api/health":
            self.send_json(
                {
                    "ok": True,
                    "status": "ok",
                    "app": "Veritas AI",
                    "product": "Evidence Threshold Engine for Splunk",
                    "mode": splunk_status()["provider"],
                    "splunk_configured": splunk_configured(),
                    "hec_configured": splunk_hec_configured(),
                    "mcp_routed": splunk_mcp_enabled(),
                    "version": APP_VERSION,
                }
            )
            return

        if path == "/api/sentinel/state":
            self.send_json(state_payload())
            return

        if path == "/api/sentinel/config":
            self.send_json(splunk_status())
            return

        if path == "/api/sentinel/incidents":
            self.send_json(
                {
                    "incident_catalog": INCIDENT_PROFILES,
                    "active_incident": incident_profile(),
                    "policy_catalog": [
                        {"id": profile_id, **profile}
                        for profile_id, profile in POLICY_PROFILES.items()
                    ],
                    "active_policy": {"id": LAB_STATE.get("policy_profile", "standard"), **policy_profile()},
                }
            )
            return

        if path == "/api/sentinel/brief":
            self.send_json({"brief": brief_text()})
            return

        if path == "/api/sentinel/case-history":
            self.send_json({"history": read_case_history()})
            return

        if not self.static_path_allowed(path):
            self.send_error(404, "Not found")
            return

        super().do_GET()

    def do_POST(self):
        if not self.require_authorized():
            return
        path = urlparse(self.path).path

        try:
            payload = self.read_json()
        except json.JSONDecodeError:
            self.send_json({"error": "Invalid JSON"}, status=400)
            return

        if path == "/api/sentinel/reset":
            clear_lab_state("idle")
            self.send_json(state_payload())
            return

        if path == "/api/sentinel/start":
            clear_lab_state("attack-running")
            self.send_json({**state_payload(), "sequence_length": len(active_attack_events())})
            return

        if path == "/api/sentinel/incidents":
            self.send_json(
                {
                    "incident_catalog": INCIDENT_PROFILES,
                    "active_incident": incident_profile(),
                    "policy_catalog": [
                        {"id": profile_id, **profile}
                        for profile_id, profile in POLICY_PROFILES.items()
                    ],
                    "active_policy": {"id": LAB_STATE.get("policy_profile", "standard"), **policy_profile()},
                }
            )
            return

        if path == "/api/sentinel/select-incident":
            result = select_incident(payload.get("incident_id") or payload.get("id"), bool(payload.get("load")))
            self.send_json(result, status=200 if result.get("ok") else 400)
            return

        if path == "/api/sentinel/policy":
            result = set_policy_profile(payload.get("profile") or payload.get("id"))
            self.send_json(result, status=200 if result.get("ok") else 400)
            return

        if path == "/api/sentinel/load-splunk":
            result = load_splunk_evidence()
            self.send_json(result, status=200 if result.get("ok") else 400)
            return

        if path == "/api/sentinel/ingest-online-feed":
            result = ingest_online_feed(load_after=payload.get("load_after", True))
            self.send_json(result, status=200 if result.get("ok") else 400)
            return

        if path == "/api/sentinel/custom-run":
            result = run_custom_request(payload)
            self.send_json(result, status=200 if result.get("ok") else 400)
            return

        if path == "/api/sentinel/step":
            event_stream = active_attack_events()
            if LAB_STATE["stage"] == "idle":
                LAB_STATE["stage"] = "attack-running"
            if len(LAB_STATE["events"]) < len(event_stream):
                LAB_STATE["events"].append(event_stream[len(LAB_STATE["events"])])
            if len(LAB_STATE["events"]) == len(event_stream):
                LAB_STATE["stage"] = "attack-complete"
            self.send_json(state_payload())
            return

        if path == "/api/sentinel/investigate":
            self.send_json(investigation_payload())
            return

        if path == "/api/sentinel/approval":
            decision_id = payload.get("decision_id")
            action = payload.get("approval")
            if action not in {"approved", "rejected"}:
                self.send_json({"error": "Approval must be approved or rejected"}, status=400)
                return
            decisions = decision_lookup()
            decision = decisions.get(decision_id)
            if decision is None:
                self.send_json({"error": "Unknown decision"}, status=400)
                return
            if not eligible_for_approval(decision):
                self.send_json({"error": "Decision is not eligible for approval"}, status=400)
                return
            LAB_STATE["approvals"][decision_id] = action
            save_last_run()
            self.send_json(state_payload())
            return

        if path == "/api/sentinel/respond":
            action_id = payload.get("action")
            action = next((item for item in RESPONSE_ACTIONS if item["id"] == action_id), None)
            if action is None:
                self.send_json({"error": "Unknown response action"}, status=400)
                return
            decision_id = ACTION_DECISION_MAP.get(action_id)
            if decision_id and LAB_STATE["approvals"].get(decision_id) != "approved":
                self.send_json(
                    {
                        "ok": False,
                        "error": "Human approval required before this action can execute.",
                    },
                    status=409,
                )
                return
            if action_id not in {item["id"] for item in LAB_STATE["actions"]}:
                LAB_STATE["actions"].append(action)
            LAB_STATE["stage"] = "contained" if calculate_risk() <= 35 else "responding"
            save_last_run()
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
