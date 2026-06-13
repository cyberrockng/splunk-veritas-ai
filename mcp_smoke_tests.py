import json
import os
import subprocess
import sys


ROOT = os.path.dirname(os.path.abspath(__file__))


def send(proc, message):
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()


def receive(proc):
    line = proc.stdout.readline()
    if not line:
        stderr = proc.stderr.read()
        raise AssertionError(f"MCP server exited early. stderr={stderr!r}")
    return json.loads(line)


def request(proc, message_id, method, params=None):
    message = {"jsonrpc": "2.0", "id": message_id, "method": method}
    if params is not None:
        message["params"] = params
    send(proc, message)
    response = receive(proc)
    if response.get("id") != message_id:
        raise AssertionError(f"expected response id {message_id}, got {response!r}")
    return response


def assert_true(value, label):
    if not value:
        raise AssertionError(label)


def assert_no_secret_like_values(value):
    text = json.dumps(value)
    blocked = ("Authorization", "bd81e8ed")
    for item in blocked:
        if item in text:
            raise AssertionError(f"secret-like value leaked: {item}")


def main():
    env = os.environ.copy()
    env["SPLUNK_HOST"] = ""
    env["SPLUNK_TOKEN"] = ""
    env["SPLUNK_HEC_URL"] = ""
    env["SPLUNK_HEC_TOKEN"] = ""

    proc = subprocess.Popen(
        [sys.executable, "splunk_mcp_server.py"],
        cwd=ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        init = request(
            proc,
            1,
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "veritas-mcp-smoke", "version": "1.0.0"},
            },
        )
        assert_true(init["result"]["capabilities"].get("tools") is not None, "tools capability")
        assert_true(init["result"]["serverInfo"]["name"] == "splunk-veritas-ai-mcp", "server name")

        send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        tools = request(proc, 2, "tools/list")
        names = {tool["name"] for tool in tools["result"]["tools"]}
        for expected in (
            "splunk.status",
            "splunk.search",
            "splunk.veritas_evidence",
            "splunk.hec_ingest_event",
            "veritas.ingest_demo_evidence",
        ):
            assert_true(expected in names, f"tool listed: {expected}")

        status = request(
            proc,
            3,
            "tools/call",
            {"name": "splunk.status", "arguments": {}},
        )
        content = status["result"]["structuredContent"]
        assert_true(content["provider"] == "splunk-mcp", "status provider")
        assert_true(content["rest_configured"] is False, "REST should be unconfigured in smoke")
        assert_true(content["hec_configured"] is False, "HEC should be unconfigured in smoke")
        assert_true(content["writes_enabled"] is False, "MCP writes should default off")
        assert_no_secret_like_values(status)

        search = request(
            proc,
            4,
            "tools/call",
            {"name": "splunk.search", "arguments": {"query": 'index="veritas" | head 1'}},
        )
        assert_true(search["result"]["isError"], "unconfigured search reports tool error")
        assert_true("SPLUNK_HOST" in search["result"]["structuredContent"]["error"], "search error explains config")
        assert_no_secret_like_values(search)

        invalid = request(
            proc,
            5,
            "tools/call",
            {"name": "splunk.notable_event", "arguments": {}},
        )
        assert_true("error" in invalid, "unknown simulated tool should not be exposed")

        write_attempt = request(
            proc,
            6,
            "tools/call",
            {
                "name": "splunk.hec_ingest_event",
                "arguments": {"event": {"event_id": "SEC-TEST"}, "confirm_ingest": True},
            },
        )
        assert_true(write_attempt["result"]["isError"], "HEC write should be disabled by default")
        assert_true(
            "VERITAS_MCP_ALLOW_WRITES" in write_attempt["result"]["structuredContent"]["error"],
            "HEC write error should explain opt-in",
        )
        print("MCP smoke tests passed.")
    finally:
        proc.stdin.close()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
