import json
import os
import subprocess
import sys
import time
from urllib import error, request


ROOT = os.path.dirname(os.path.abspath(__file__))
BASE_URL = "http://127.0.0.1:5175"


def request_json(path, method="GET", payload=None):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = request.Request(f"{BASE_URL}{path}", data=data, method=method, headers=headers)
    with request.urlopen(req, timeout=10) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


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


def wait_for_server():
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            status, payload = request_json("/api/health")
            if status == 200 and payload.get("ok"):
                return payload
        except Exception:
            time.sleep(0.5)
    raise AssertionError("dashboard MCP route test server did not become healthy")


def main():
    env = os.environ.copy()
    env.update(
        {
            "PORT": "5175",
            "SPLUNK_HOST": "http://127.0.0.1:1",
            "SPLUNK_TOKEN": "test-token",
            "SPLUNK_AUTH_SCHEME": "Bearer",
            "SPLUNK_VERIFY_SSL": "false",
            "SPLUNK_TIMEOUT": "1",
            "SPLUNK_SEARCH_POLLS": "1",
            "VERITAS_SPLUNK_ROUTE": "mcp",
            "SPLUNK_MCP_SERVER": os.path.join(ROOT, "splunk_mcp_server.py"),
        }
    )
    proc = subprocess.Popen(
        [sys.executable, "server.py"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        health = wait_for_server()
        assert_equal(health["mode"], "splunk-mcp", "health mode")
        assert_true(health["splunk_configured"], "Splunk configured flag")
        assert_true(health["mcp_routed"], "health MCP routed flag")

        status, config = request_json("/api/sentinel/config")
        assert_equal(status, 200, "config status")
        assert_equal(config["provider"], "splunk-mcp", "config provider")
        assert_true(config["mcp_routed"], "config MCP routed flag")
        assert_true("token" not in json.dumps(config).lower(), "config should not expose token")

        status, body = request_json_error("/api/sentinel/load-splunk", method="POST", payload={})
        assert_equal(status, 400, "load-splunk failure status")
        assert_true("MCP" in body["error"], "load-splunk should report MCP route")
        assert_equal(body["search"]["provider"], "splunk-mcp", "failed load provider")
        assert_true(body["search"]["mcp_routed"], "failed load MCP routed flag")
        assert_true("test-token" not in json.dumps(body), "failure response should not expose token")
        print("Dashboard MCP route tests passed.")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    main()
