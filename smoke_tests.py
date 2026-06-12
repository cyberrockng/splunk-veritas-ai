from urllib import error, request
import json
import os
import sys


BASE_URL = os.environ.get("VERITAS_BASE_URL", "http://127.0.0.1:5173")
REQUEST_TIMEOUT = int(os.environ.get("VERITAS_REQUEST_TIMEOUT", "10"))


def request_json(path, method="GET", payload=None):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = request.Request(f"{BASE_URL}{path}", data=data, method=method, headers=headers)
    with request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


def request_json_error(path, method="GET", payload=None):
    try:
        request_json(path, method=method, payload=payload)
    except error.HTTPError as http_error:
        return http_error.code, json.loads(http_error.read().decode("utf-8"))
    raise AssertionError(f"{path} should have returned an HTTP error")


def request_text(path):
    req = request.Request(f"{BASE_URL}{path}", method="GET")
    with request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
        return response.status, response.read().decode("utf-8")


def request_bytes(path):
    req = request.Request(f"{BASE_URL}{path}", method="GET")
    with request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
        return response.status, response.read()


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
    assert_equal(health["status"], "ok", "health status")
    assert_equal(health["app"], "Veritas AI", "health app")
    assert_equal(health["product"], "Evidence Threshold Engine for Splunk", "health product")
    assert_true(health["mode"] in {"mock-mcp", "splunk-rest"}, "health mode")
    assert_true(isinstance(health["splunk_configured"], bool), "health Splunk configured flag")
    assert_equal(health["mode"], "splunk-rest" if health["splunk_configured"] else "mock-mcp", "health mode/config alignment")
    assert_true(health["version"], "health version")
    assert_true("token" not in json.dumps(health).lower(), "health must not expose tokens")

    for asset_path, expected_text in (
        ("/index.html", "VERITAS AI"),
        ("/detail.html", "Tier 3 Decision Detail"),
        ("/styles.css", "--sidebar"),
        ("/app.js", "API_BASE"),
        ("/detail.js", "API_BASE"),
    ):
        status, text = request_text(asset_path)
        assert_equal(status, 200, f"{asset_path} static status")
        assert_true(expected_text in text, f"{asset_path} static content")
        assert_true("Tier 2" not in text, f"{asset_path} should not mention Tier 2")
        assert_true("SentinelOps" not in text, f"{asset_path} should not mention SentinelOps")
        if asset_path == "/index.html":
            assert_true("Started: live Splunk session" not in text, "index should not claim live Splunk by default")
            assert_true("Evidence source:" in text, "index should show evidence source copy")

    for image_path in (
        "/assets/dashboard.png",
        "/assets/decision-readiness-strip.png",
        "/assets/evidence-threshold-matrix.png",
        "/assets/audit-brief.png",
        "/assets/splunk-mode.png",
    ):
        status, body = request_bytes(image_path)
        assert_equal(status, 200, f"{image_path} image status")
        assert_true(len(body) > 1000, f"{image_path} image content")

    catalog = request_json("/api/sentinel/incidents")
    assert_true(len(catalog["incident_catalog"]) >= 3, "Tier 3 incident catalog")
    assert_true(len(catalog["policy_catalog"]) >= 3, "Tier 3 policy catalog")

    cloud_profile = request_json(
        "/api/sentinel/select-incident",
        method="POST",
        payload={"incident_id": "cloud-key-abuse", "load": True},
    )
    assert_equal(cloud_profile["incident"]["id"], "cloud-key-abuse", "selected cloud incident")
    assert_equal(cloud_profile["policy"]["id"], "strict", "cloud incident recommended policy")
    assert_true(cloud_profile["events"], "selected incident should load events")

    emergency_policy = request_json(
        "/api/sentinel/policy",
        method="POST",
        payload={"profile": "emergency"},
    )
    assert_equal(emergency_policy["policy"]["id"], "emergency", "policy profile switch")

    request_json(
        "/api/sentinel/select-incident",
        method="POST",
        payload={"incident_id": "admin-takeover", "load": False},
    )

    initial_state = request_json("/api/sentinel/state")
    assert_equal(len(initial_state["decisions"]), 5, "state endpoint decision count")
    assert_equal(len(initial_state["readiness_strip"]), 5, "decision readiness strip count")
    assert_true("integration" in initial_state, "state endpoint should include integration metadata")
    assert_equal(
        initial_state["integration"]["provider"],
        "splunk-rest" if health["splunk_configured"] else "mock-mcp",
        "state provider should match health mode",
    )

    config = request_json("/api/sentinel/config")
    assert_true(config["index"], "config should include Veritas Splunk index")
    assert_true(config["incident_id"], "config should include incident id")
    assert_true("token" not in json.dumps(config).lower(), "config must not expose tokens")
    if not config["configured"]:
        status, body = request_json_error("/api/sentinel/load-splunk", method="POST", payload={})
        assert_equal(status, 400, "load-splunk without config status")
        assert_true("Splunk REST is not configured" in body["error"], "load-splunk config error")
    elif os.environ.get("VERITAS_SMOKE_SPLUNK") == "1":
        splunk_load = request_json("/api/sentinel/load-splunk", method="POST", payload={})
        assert_equal(splunk_load["integration"]["provider"], "splunk-rest", "Splunk load provider")
        assert_true("search" in splunk_load, "Splunk load should include search proof")
        assert_true(splunk_load["search"]["result_count"] >= 0, "Splunk load result count")

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
    assert_true(investigation["tool_calls"], "integration-ready Splunk tool calls should be present")

    revoke = decision_by_title(investigation, "Revoke session token")
    disable = decision_by_title(investigation, "Disable admin account")
    block_ip = decision_by_title(investigation, "Block source IP")
    data_statement = decision_by_title(investigation, "Declare no sensitive data accessed")
    close_incident = decision_by_title(investigation, "Close incident as contained")

    assert_equal(revoke["status"], "Approved", "revoke decision status")
    assert_true(disable["status"] in {"Approved", "Caution"}, "disable decision status")
    assert_equal(block_ip["status"], "Caution", "block IP decision status")
    assert_true(block_ip["blast_radius"], "block IP should include blast radius warning")
    assert_equal(data_statement["status"], "Blocked", "data access statement status")
    assert_true(close_incident["status"] in {"Not Ready", "Blocked"}, "close incident status")
    assert_true(data_statement["recommended_spl"], "blocked decision should include SPL gaps")
    assert_true(close_incident["recommended_spl"], "closure gap should include SPL")
    assert_true(investigation["integrity"]["sources_missing"], "integrity panel should show blind spots")
    assert_true(
        "Missing logs" in investigation["integrity"]["missing_telemetry_warning"],
        "integrity should warn that missing logs are not safety proof",
    )
    assert_true(
        "untrusted evidence" in investigation["integrity"]["prompt_injection_warning"],
        "integrity should warn that logs are untrusted evidence",
    )
    assert_true(
        "High-impact" in investigation["integrity"]["human_approval_requirement"],
        "integrity should state human approval requirement",
    )
    assert_equal(len(investigation["approvals"]), 3, "approval gate action count")

    status, body = request_json_error("/api/sentinel/respond", method="POST", payload={"action": "revoke-token"})
    assert_equal(status, 409, "unapproved action should be blocked")
    assert_equal(body["ok"], False, "approval required ok false")
    assert_true("Human approval required" in body["error"], "approval required error")

    status, body = request_json_error("/api/sentinel/respond", method="POST", payload={"action": "disable-account"})
    assert_equal(status, 409, "unapproved high-impact action should be blocked")
    assert_equal(body["ok"], False, "high-impact approval required ok false")
    assert_true("Human approval required" in body["error"], "high-impact approval required error")

    contained = investigation
    for decision_id in ("revoke-session", "disable-admin", "block-source-ip"):
        contained = request_json(
            "/api/sentinel/approval",
            method="POST",
            payload={"decision_id": decision_id, "approval": "approved"},
        )
    assert_true(
        all(
            item["approval"] == "approved"
            for item in contained["approvals"]
            if item["decision_id"] in {"revoke-session", "disable-admin", "block-source-ip"}
        ),
        "eligible actions should be approved",
    )

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
    assert_true("Veritas AI Tier 3 Decision Audit Brief" in brief["brief"], "brief title")
    assert_true("Generated by Veritas AI" in brief["brief"], "brief generated-by line")
    assert_true("Generated at:" in brief["brief"], "brief timestamp")
    assert_true("Prepared for Tier 3 incident-response review" in brief["brief"], "brief tier 3 review line")
    assert_true("Risk score:" in brief["brief"], "brief risk")
    assert_true("Search provider:" in brief["brief"], "brief source provider")
    assert_true("Executive decision summary" in brief["brief"], "brief executive section")
    assert_true("Approved or caution-ready decisions" in brief["brief"], "brief approved section")
    assert_true("Blocked or not-ready decisions" in brief["brief"], "brief blocked section")
    assert_true("Decision readiness details" in brief["brief"], "brief decision detail section")
    assert_true("Proposed decision:" in brief["brief"], "brief proposed decision")
    assert_true("Readiness score:" in brief["brief"], "brief readiness score")
    assert_true("Status:" in brief["brief"], "brief status")
    assert_true("Evidence found:" in brief["brief"], "brief found evidence")
    assert_true("Evidence missing:" in brief["brief"], "brief missing evidence")
    assert_true("Blast radius:" in brief["brief"], "brief blast radius")
    assert_true("Recommended next action:" in brief["brief"], "brief next action")
    assert_true("Human approval requirement:" in brief["brief"], "brief human approval")
    assert_true("Safety notes:" in brief["brief"], "brief safety notes")
    assert_true("Missing logs are not proof of safety." in brief["brief"], "brief missing logs safety note")
    assert_true("Splunk evidence provenance" in brief["brief"], "brief provenance section")
    assert_true("Threshold search jobs" in brief["brief"], "brief search job section")
    assert_true("Analyst approval gate" in brief["brief"], "brief approval gate section")
    assert_true("Missing evidence and SPL" in brief["brief"], "brief SPL gap section")

    custom = request_json(
        "/api/sentinel/custom-run",
        method="POST",
        payload={
            "title": "Custom MFA session containment",
            "evidence": "Admin login from a new country with impossible travel and repeated MFA fatigue prompts followed by approval.",
            "action": "revoke-token",
            "execute": True,
        },
    )
    assert_equal(custom["integration"]["provider"], "custom-input", "custom provider")
    assert_equal(custom["integration"]["request"]["title"], "Custom MFA session containment", "custom title")
    assert_equal(len(custom["events"]), 3, "custom event mapping")
    assert_true(custom["risk"] != 12, "custom request should recalculate risk")
    assert_true(custom["integration"]["request"]["feedback"]["executed"], "custom feedback should mark execution")
    assert_equal(
        custom["integration"]["request"]["feedback"]["decision_status"],
        "Approved",
        "custom feedback decision status",
    )
    assert_equal(
        next(item for item in custom["actions"] if item["id"] == "revoke-token")["status"],
        "completed",
        "custom request should execute approved task",
    )

    weak_custom = request_json(
        "/api/sentinel/custom-run",
        method="POST",
        payload={
            "title": "Weak evidence block request",
            "evidence": "Analyst saw one normal admin login and wants to block the source IP.",
            "action": "block-ip",
            "execute": True,
        },
    )
    assert_equal(weak_custom["integration"]["provider"], "custom-input", "weak custom provider")
    assert_true(
        not weak_custom["integration"]["request"]["feedback"]["executed"],
        "weak custom request should be held",
    )
    assert_true(
        weak_custom["integration"]["request"]["feedback"]["missing_evidence"],
        "weak custom request should explain missing evidence",
    )

    request_json("/api/sentinel/reset", method="POST", payload={})
    print("Smoke tests passed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Smoke tests failed: {error}", file=sys.stderr)
        sys.exit(1)
