from urllib import error, request
import base64
import json
import os


BASE_URL = os.environ.get("VERITAS_BASE_URL", "http://127.0.0.1:5173")
REQUEST_TIMEOUT = int(os.environ.get("VERITAS_REQUEST_TIMEOUT", "10"))
AUTH_TOKEN = os.environ.get("VERITAS_AUTH_TOKEN", "")
AUTH_USER = os.environ.get("VERITAS_AUTH_USER", "veritas")
EXPECT_AUTH = os.environ.get("VERITAS_EXPECT_AUTH", "").lower() in {"1", "true", "yes"}


def auth_headers():
    if not AUTH_TOKEN:
        return {}
    return {"X-Veritas-Auth": AUTH_TOKEN}


def request_raw(path, headers=None):
    req = request.Request(f"{BASE_URL}{path}", method="GET", headers=headers or {})
    return request.urlopen(req, timeout=REQUEST_TIMEOUT)


def request_status(path, headers=None):
    try:
        with request_raw(path, headers=headers) as response:
            return response.status, response.read(), response.headers
    except error.HTTPError as http_error:
        return http_error.code, http_error.read(), http_error.headers


def assert_true(value, label):
    if not value:
        raise AssertionError(label)


def assert_equal(actual, expected, label):
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


def assert_blocked(path):
    status, body, _ = request_status(path, headers=auth_headers())
    assert_true(status in {400, 403, 404}, f"{path} should be blocked, got HTTP {status}: {body[:80]!r}")


def main():
    if EXPECT_AUTH:
        status, _, unauth_headers = request_status("/api/health")
        assert_equal(status, 401, "unauthenticated health should be blocked")
        assert_true("Basic" in unauth_headers.get("WWW-Authenticate", ""), "auth challenge should use Basic")

        basic = base64.b64encode(f"{AUTH_USER}:{AUTH_TOKEN}".encode("utf-8")).decode("ascii")
        status, body, _ = request_status("/api/health", headers={"Authorization": f"Basic {basic}"})
        assert_equal(status, 200, "Basic auth should be accepted")
        assert_true(json.loads(body.decode("utf-8"))["ok"], "authenticated health payload")

    status, body, headers = request_status("/api/health", headers=auth_headers())
    assert_equal(status, 200, "health status")
    assert_true(json.loads(body.decode("utf-8"))["ok"], "health ok")
    assert_equal(headers.get("X-Content-Type-Options"), "nosniff", "nosniff header")
    assert_equal(headers.get("Referrer-Policy"), "no-referrer", "referrer policy")
    assert_true(headers.get("Content-Security-Policy"), "content security policy header")
    assert_true(b"SPLUNK_TOKEN" not in body and b"SPLUNK_HEC_TOKEN" not in body, "health must not expose secret names")

    status, body, _ = request_status("/styles.css", headers=auth_headers())
    assert_equal(status, 200, "allowed CSS asset")
    assert_true(len(body) > 1000, "CSS body should be non-empty")

    for blocked_path in (
        "/server.py",
        "/splunk_mcp_server.py",
        "/.env",
        "/.env.example",
        "/README.md",
        "/..%2Fserver.py",
        "/assets/..%2Fserver.py",
    ):
        assert_blocked(blocked_path)

    allowed_origin = os.environ.get("VERITAS_ALLOWED_ORIGIN", "http://127.0.0.1:5173")
    status, _, allowed_headers = request_status("/api/health", headers={**auth_headers(), "Origin": allowed_origin})
    assert_equal(status, 200, "allowed-origin health")
    assert_equal(allowed_headers.get("Access-Control-Allow-Origin"), allowed_origin, "allowed CORS origin")

    status, _, denied_headers = request_status("/api/health", headers={**auth_headers(), "Origin": "https://evil.example"})
    assert_equal(status, 200, "denied-origin health still responds")
    assert_true(not denied_headers.get("Access-Control-Allow-Origin"), "unknown CORS origin should not be allowed")

    print("Deployment security tests passed.")


if __name__ == "__main__":
    main()
