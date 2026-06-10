from urllib import error, request
import json
import sys


BASE_URL = "http://127.0.0.1:5173"


def request_json(path, method="GET", payload=None):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = request.Request(f"{BASE_URL}{path}", data=data, method=method, headers=headers)
    with request.urlopen(req, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def request_json_error(path, method="GET", payload=None):
    try:
        request_json(path, method=method, payload=payload)
    except error.HTTPError as http_error:
        return http_error.code, json.loads(http_error.read().decode("utf-8"))
    raise AssertionError(f"{path} should have returned an HTTP error")


def assert_equal(actual, expected, label):
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


def assert_true(value, label):
    if not value:
        raise AssertionError(label)


def decision_by_title(state, title):
    return next(decision for decision in state["decisions"] if decision["title"] == title)


def main():
    health = request_json("/api/health")
    assert_true(health["ok"], "health endpoint should be ok")

    config = request_json("/api/sentinel/config")
    assert_true(config["index"], "config should include Veritas Splunk index")
    assert_true(config["incident_id"], "config should include incident id")
    if not config["configured"]:
        status, body = request_json_error("/api/sentinel/load-splunk", method="POST", payload={})
        assert_equal(status, 400, "load-splunk without config status")
        assert_true("Splunk REST is not configured" in body["error"], "load-splunk config error")

    reset = request_json("/api/sentinel/reset", method="POST", payload={})
    assert_equal(reset["stage"], "idle", "reset stage")
    assert_equal(reset["risk"], 12, "reset risk")
    assert_equal(len(reset["decisions"]), 5, "decision count")

    started = request_json("/api/sentinel/start", method="POST", payload={})
    assert_equal(started["sequence_length"], 6, "attack sequence length")

    state = started
    for _ in range(started["sequence_length"]):
        state = request_json("/api/sentinel/step", method="POST", payload={})

    assert_equal(state["stage"], "attack-complete", "attack completion stage")
    assert_equal(len(state["events"]), 6, "streamed event count")

    investigation = request_json("/api/sentinel/investigate", method="POST", payload={})
    assert_equal(len(investigation["detections"]), 4, "detection count")
    assert_equal(len(investigation["decisions"]), 5, "decision count after investigation")
    assert_true(investigation["tool_calls"], "MCP-shaped tool calls should be present")

    revoke = decision_by_title(investigation, "Revoke session token")
    disable = decision_by_title(investigation, "Disable admin account")
    block_ip = decision_by_title(investigation, "Block source IP")
    data_statement = decision_by_title(investigation, "Declare no sensitive data accessed")
    close_incident = decision_by_title(investigation, "Close incident as contained")

    assert_equal(revoke["status"], "Approved", "revoke decision status")
    assert_true(disable["status"] in {"Approved", "Caution"}, "disable decision status")
    assert_equal(block_ip["status"], "Caution", "block IP decision status")
    assert_equal(data_statement["status"], "Blocked", "data access statement status")
    assert_true(close_incident["status"] in {"Not Ready", "Blocked"}, "close incident status")
    assert_true(data_statement["recommended_spl"], "blocked decision should include SPL gaps")
    assert_true(investigation["integrity"]["sources_missing"], "integrity panel should show blind spots")

    contained = investigation
    for action_id in ("revoke-token", "disable-account", "block-ip"):
        contained = request_json("/api/sentinel/respond", method="POST", payload={"action": action_id})

    assert_true(contained["stage"] in {"responding", "contained"}, "post-action stage")
    assert_true(contained["risk"] < investigation["risk"], "containment should reduce risk")

    post_action = request_json("/api/sentinel/investigate", method="POST", payload={})
    close_after_action = decision_by_title(post_action, "Close incident as contained")
    data_after_action = decision_by_title(post_action, "Declare no sensitive data accessed")
    assert_true(
        close_after_action["status"] in {"Not Ready", "Blocked"},
        "closure should still require post-containment evidence",
    )
    assert_equal(data_after_action["status"], "Blocked", "data access statement remains blocked")

    brief = request_json("/api/sentinel/brief")
    assert_true("Veritas AI Decision Audit Brief" in brief["brief"], "brief title")
    assert_true("Decision readiness" in brief["brief"], "brief decision section")
    assert_true("Missing evidence and SPL" in brief["brief"], "brief SPL gap section")

    request_json("/api/sentinel/reset", method="POST", payload={})
    print("Smoke tests passed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Smoke tests failed: {error}", file=sys.stderr)
        sys.exit(1)
