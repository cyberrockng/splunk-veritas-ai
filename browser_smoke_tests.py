from urllib import request
import json
import os
import re
import sys


BASE_URL = os.environ.get("VERITAS_BASE_URL", "http://127.0.0.1:5173")
REQUEST_TIMEOUT = int(os.environ.get("VERITAS_REQUEST_TIMEOUT", "10"))


def request_text(path):
    req = request.Request(f"{BASE_URL}{path}", method="GET")
    with request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
        return response.status, response.read().decode("utf-8")


def request_json(path, method="GET", payload=None):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = request.Request(f"{BASE_URL}{path}", data=data, method=method, headers=headers)
    with request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


def assert_true(value, label):
    if not value:
        raise AssertionError(label)


def assert_equal(actual, expected, label):
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


def assert_contains(text, expected, label):
    assert_true(expected in text, f"{label}: missing {expected!r}")


def assert_no_secret_like_values(text, label):
    blocked_patterns = (
        r"SPLUNK_HEC_TOKEN\s*=",
        r"SPLUNK_TOKEN\s*=",
        r"Authorization:\s*Splunk\s+",
        r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    )
    for pattern in blocked_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            raise AssertionError(f"{label}: secret-like value matched {pattern}")


def decision_by_id(state, decision_id):
    return next(decision for decision in state["decisions"] if decision["id"] == decision_id)


def verify_browser_shell():
    status, index = request_text("/index.html")
    assert_equal(status, 200, "index page status")
    for expected in (
        "VERITAS AI",
        'id="judgeModeBtn"',
        'id="loadSplunkBtn"',
        'id="executeSafeBtn"',
        'id="incidentSelector"',
        'id="policySelector"',
        'id="customDialog"',
        'id="briefDialog"',
        'id="evidenceDialog"',
        "Run Live Judge Demo",
        "Pull Indexed Evidence",
        "Execute Approved Containment",
        "detail.html?view=matrix",
        "detail.html?view=audit",
    ):
        assert_contains(index, expected, "index browser shell")
    assert_no_secret_like_values(index, "index page")

    status, detail = request_text("/detail.html")
    assert_equal(status, 200, "detail page status")
    for expected in (
        "Tier 3 Decision Detail",
        'id="detailRisk"',
        'id="detailProvider"',
        'id="detailMode"',
        'id="detailEvents"',
        'id="detailStage"',
        'id="detailContent"',
        'id="detailCustomForm"',
        'id="detailBriefDialog"',
        "Run Custom Request",
    ):
        assert_contains(detail, expected, "detail browser shell")
    assert_no_secret_like_values(detail, "detail page")


def run_demo_flow():
    health = request_json("/api/health")
    assert_true(health["ok"], "health should be ok")
    assert_true(health["mode"] in {"mock-mcp", "splunk-rest"}, "health mode should be known")

    state = request_json("/api/sentinel/reset", method="POST", payload={})
    assert_equal(state["stage"], "idle", "reset stage")

    started = request_json("/api/sentinel/start", method="POST", payload={})
    assert_equal(started["sequence_length"], 6, "judge demo event count")

    state = started
    for _ in range(started["sequence_length"]):
        state = request_json("/api/sentinel/step", method="POST", payload={})
    assert_equal(state["stage"], "attack-complete", "demo should stream all events")

    investigation = request_json("/api/sentinel/investigate", method="POST", payload={})
    assert_equal(len(investigation["events"]), 6, "investigation event count")
    assert_equal(decision_by_id(investigation, "revoke-session")["status"], "Approved", "revoke readiness")
    assert_equal(decision_by_id(investigation, "declare-no-data-access")["status"], "Blocked", "unsafe declaration")
    assert_true(
        decision_by_id(investigation, "close-contained")["status"] in {"Not Ready", "Blocked"},
        "closure should remain gated",
    )

    for decision_id in ("revoke-session", "disable-admin", "block-source-ip"):
        state = request_json(
            "/api/sentinel/approval",
            method="POST",
            payload={"decision_id": decision_id, "approval": "approved"},
        )
    assert_true(
        all(item["approval"] == "approved" for item in state["approvals"]),
        "all eligible actions should be approved",
    )

    for action_id in ("revoke-token", "disable-account", "block-ip"):
        state = request_json("/api/sentinel/respond", method="POST", payload={"action": action_id})
    assert_true(state["risk"] < investigation["risk"], "approved containment should reduce risk")
    assert_true(state["stage"] in {"responding", "contained"}, "post-containment stage")

    brief = request_json("/api/sentinel/brief")
    for expected in (
        "Veritas AI Tier 3 Decision Audit Brief",
        "Search provider:",
        "Dashboard tool envelopes:",
        "True MCP server tools:",
        "Missing logs are not proof of safety.",
        "Declare no sensitive data accessed: Blocked",
    ):
        assert_contains(brief["brief"], expected, "audit brief")


def main():
    verify_browser_shell()
    run_demo_flow()
    request_json("/api/sentinel/reset", method="POST", payload={})
    print("Browser/demo smoke tests passed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Browser/demo smoke tests failed: {error}", file=sys.stderr)
        sys.exit(1)
