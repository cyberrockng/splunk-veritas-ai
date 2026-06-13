from datetime import datetime, timezone
import base64
import json
import os
import ssl
import sys
import time
from urllib import parse, request

from ingest_to_splunk import DEFAULT_SAMPLE_FILE, hec_event, load_events, normalize_hec_url
from server import (
    APP_VERSION,
    VERITAS_DISPLAY_INCIDENT_ID,
    VERITAS_INCIDENT_ID,
    VERITAS_SOURCETYPE,
    VERITAS_SPLUNK_INDEX,
)


PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "splunk-veritas-ai-mcp"
SERVER_TITLE = "Splunk Veritas AI MCP Server"


def env_bool(name, default=True):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() not in {"0", "false", "no"}


def splunk_config():
    return {
        "host": os.environ.get("SPLUNK_HOST", "").rstrip("/"),
        "token": os.environ.get("SPLUNK_TOKEN", ""),
        "auth_scheme": os.environ.get("SPLUNK_AUTH_SCHEME", "Bearer"),
        "verify_ssl": env_bool("SPLUNK_VERIFY_SSL", True),
        "timeout": int(os.environ.get("SPLUNK_TIMEOUT", "8")),
        "max_results": int(os.environ.get("SPLUNK_MAX_RESULTS", "25")),
        "search_polls": int(os.environ.get("SPLUNK_SEARCH_POLLS", "20")),
        "poll_interval": float(os.environ.get("SPLUNK_SEARCH_POLL_INTERVAL", "0.5")),
        "earliest": os.environ.get("SPLUNK_EARLIEST", "-60m"),
        "latest": os.environ.get("SPLUNK_LATEST", "now"),
        "index": os.environ.get("VERITAS_SPLUNK_INDEX", VERITAS_SPLUNK_INDEX),
        "sourcetype": os.environ.get("VERITAS_SOURCETYPE", VERITAS_SOURCETYPE),
        "incident_id": os.environ.get("VERITAS_INCIDENT_ID", VERITAS_INCIDENT_ID),
        "display_incident_id": os.environ.get("VERITAS_DISPLAY_INCIDENT_ID", VERITAS_DISPLAY_INCIDENT_ID),
        "hec_url": os.environ.get("SPLUNK_HEC_URL", ""),
        "hec_token": os.environ.get("SPLUNK_HEC_TOKEN", ""),
        "allow_writes": env_bool("VERITAS_MCP_ALLOW_WRITES", False),
    }


def ssl_context(verify_ssl):
    if verify_ssl:
        return None
    return ssl._create_unverified_context()


def auth_header(config):
    if config["auth_scheme"].lower() == "basic":
        encoded = base64.b64encode(config["token"].encode("utf-8")).decode("ascii")
        return f"Basic {encoded}"
    return f"{config['auth_scheme']} {config['token']}"


def splunk_request(path, params=None, method="GET"):
    config = splunk_config()
    if not config["host"] or not config["token"]:
        raise RuntimeError("Splunk REST is not configured. Set SPLUNK_HOST and SPLUNK_TOKEN.")

    url = f"{config['host']}{path}"
    data = None
    if params:
        encoded = parse.urlencode(params).encode("utf-8")
        if method == "GET":
            url = f"{url}?{encoded.decode('utf-8')}"
        else:
            data = encoded

    req = request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": auth_header(config),
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    with request.urlopen(
        req,
        timeout=config["timeout"],
        context=ssl_context(config["verify_ssl"]),
    ) as response:
        return json.loads(response.read().decode("utf-8"))


def splunk_search(query, earliest=None, latest=None, count=None):
    config = splunk_config()
    search_text = query.strip()
    if not search_text:
        raise ValueError("query is required")
    if not search_text.startswith("|") and not search_text.startswith("search "):
        search_text = f"search {search_text}"

    created = splunk_request(
        "/services/search/jobs",
        {
            "search": search_text,
            "earliest_time": earliest or config["earliest"],
            "latest_time": latest or config["latest"],
            "output_mode": "json",
        },
        method="POST",
    )
    sid = created.get("sid")
    if not sid:
        raise RuntimeError("Splunk did not return a search SID")

    dispatch_state = "UNKNOWN"
    quoted_sid = parse.quote(sid, safe="")
    for _ in range(config["search_polls"]):
        status = splunk_request(
            f"/services/search/jobs/{quoted_sid}",
            {"output_mode": "json"},
        )
        entry = (status.get("entry") or [{}])[0]
        content = entry.get("content", {})
        dispatch_state = content.get("dispatchState", dispatch_state)
        if content.get("isDone"):
            break
        time.sleep(config["poll_interval"])

    results = splunk_request(
        f"/services/search/jobs/{quoted_sid}/results",
        {
            "output_mode": "json",
            "count": count or config["max_results"],
        },
    )
    rows = results.get("results", [])
    return {
        "provider": "splunk-mcp",
        "job_id": sid,
        "dispatch_state": dispatch_state,
        "result_count": len(rows),
        "rows": rows,
        "link": f"{config['host']}/app/search/search?sid={parse.quote(sid)}",
    }


def hec_context(config):
    return ssl_context(config["verify_ssl"])


def send_hec_payload(payload):
    config = splunk_config()
    if not config["hec_url"] or not config["hec_token"]:
        raise RuntimeError("Splunk HEC is not configured. Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN.")

    req = request.Request(
        normalize_hec_url(config["hec_url"]),
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Splunk {config['hec_token']}",
            "Content-Type": "application/json",
        },
    )
    with request.urlopen(req, timeout=config["timeout"], context=hec_context(config)) as response:
        return json.loads(response.read().decode("utf-8"))


def tool_status(_arguments):
    config = splunk_config()
    status = {
        "provider": "splunk-mcp",
        "rest_configured": bool(config["host"] and config["token"]),
        "hec_configured": bool(config["hec_url"] and config["hec_token"]),
        "host": config["host"] or None,
        "index": config["index"],
        "sourcetype": config["sourcetype"],
        "incident_id": config["incident_id"],
        "display_incident_id": config["display_incident_id"],
        "verify_ssl": config["verify_ssl"],
        "writes_enabled": config["allow_writes"],
        "version": APP_VERSION,
    }
    return ok_result(status)


def require_write_confirmation(arguments):
    config = splunk_config()
    if not config["allow_writes"]:
        raise RuntimeError("MCP write tools are disabled. Set VERITAS_MCP_ALLOW_WRITES=true to allow HEC ingestion.")
    if arguments.get("confirm_ingest") is not True:
        raise RuntimeError("confirm_ingest=true is required before writing events to Splunk HEC.")


def tool_search(arguments):
    result = splunk_search(
        arguments.get("query", ""),
        earliest=arguments.get("earliest"),
        latest=arguments.get("latest"),
        count=arguments.get("count"),
    )
    return ok_result(result)


def tool_veritas_search(arguments):
    config = splunk_config()
    incident_id = arguments.get("incident_id") or config["incident_id"]
    sourcetype = arguments.get("sourcetype") or config["sourcetype"]
    index = arguments.get("index") or config["index"]
    query = (
        f'index="{splunk_escape(index)}" sourcetype="{splunk_escape(sourcetype)}" '
        f'| spath | search incident_id="{splunk_escape(incident_id)}" '
        "| table _time event_id incident_id source_category user src_ip severity action summary message"
    )
    result = splunk_search(
        query,
        earliest=arguments.get("earliest"),
        latest=arguments.get("latest"),
        count=arguments.get("count"),
    )
    return ok_result(result)


def tool_hec_ingest_event(arguments):
    require_write_confirmation(arguments)
    config = splunk_config()
    event = arguments.get("event")
    if not isinstance(event, dict):
        raise ValueError("event must be an object")
    payload = {
        "time": arguments.get("time", time.time()),
        "host": arguments.get("host", "veritas-mcp"),
        "source": arguments.get("source", "veritas-ai-mcp"),
        "sourcetype": arguments.get("sourcetype", config["sourcetype"]),
        "index": arguments.get("index", config["index"]),
        "event": event,
    }
    result = send_hec_payload(payload)
    return ok_result({"provider": "splunk-mcp", "hec_result": result, "event_id": event.get("event_id")})


def tool_ingest_demo(arguments):
    require_write_confirmation(arguments)
    config = splunk_config()
    sample_file = arguments.get("sample_file") or DEFAULT_SAMPLE_FILE
    events = load_events(sample_file)
    incident_id = arguments.get("incident_id") or config["incident_id"]
    display_incident_id = arguments.get("display_incident_id") or config["display_incident_id"]
    index = arguments.get("index") or config["index"]
    sourcetype = arguments.get("sourcetype") or config["sourcetype"]
    start_time = time.time() - 300
    ingested = []
    failures = []

    for offset, event in enumerate(events):
        payload = hec_event(event, index, incident_id, display_incident_id, sourcetype, start_time + offset)
        event_id = payload["event"]["event_id"]
        try:
            result = send_hec_payload(payload)
        except Exception as error:
            failures.append({"event_id": event_id, "error": str(error)})
            continue
        if result.get("code") == 0:
            ingested.append(event_id)
        else:
            failures.append({"event_id": event_id, "error": result})

    if failures:
        return error_result(
            {
                "provider": "splunk-mcp",
                "ingested": ingested,
                "failures": failures,
                "index": index,
                "sourcetype": sourcetype,
            }
        )
    return ok_result(
        {
            "provider": "splunk-mcp",
            "ingested": ingested,
            "count": len(ingested),
            "index": index,
            "sourcetype": sourcetype,
        }
    )


def splunk_escape(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def json_text(value):
    return json.dumps(value, indent=2, sort_keys=True)


def ok_result(value):
    return {
        "content": [{"type": "text", "text": json_text(value)}],
        "structuredContent": value,
        "isError": False,
    }


def error_result(value):
    return {
        "content": [{"type": "text", "text": json_text(value)}],
        "structuredContent": value,
        "isError": True,
    }


TOOLS = {
    "splunk.status": {
        "handler": tool_status,
        "definition": {
            "name": "splunk.status",
            "title": "Splunk MCP Status",
            "description": "Report whether Splunk REST and HEC are configured without exposing tokens.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    "splunk.search": {
        "handler": tool_search,
        "definition": {
            "name": "splunk.search",
            "title": "Splunk REST Search",
            "description": "Run a real Splunk REST search job and return result rows, job ID, and a Splunk result link.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "SPL query to dispatch. A leading search is added when omitted."},
                    "earliest": {"type": "string", "description": "Splunk earliest_time, for example -60m."},
                    "latest": {"type": "string", "description": "Splunk latest_time, for example now."},
                    "count": {"type": "integer", "minimum": 1, "maximum": 1000},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
        },
    },
    "splunk.veritas_evidence": {
        "handler": tool_veritas_search,
        "definition": {
            "name": "splunk.veritas_evidence",
            "title": "Veritas Evidence Search",
            "description": "Search indexed Veritas incident evidence in Splunk using the configured index, sourcetype, and incident ID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "incident_id": {"type": "string"},
                    "index": {"type": "string"},
                    "sourcetype": {"type": "string"},
                    "earliest": {"type": "string"},
                    "latest": {"type": "string"},
                    "count": {"type": "integer", "minimum": 1, "maximum": 1000},
                },
                "additionalProperties": False,
            },
        },
    },
    "splunk.hec_ingest_event": {
        "handler": tool_hec_ingest_event,
        "definition": {
            "name": "splunk.hec_ingest_event",
            "title": "Splunk HEC Ingest Event",
            "description": "Write one event to Splunk HEC. Use only with explicit human approval.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "event": {"type": "object", "description": "Event object to index through HEC."},
                    "index": {"type": "string"},
                    "sourcetype": {"type": "string"},
                    "host": {"type": "string"},
                    "source": {"type": "string"},
                    "time": {"type": "number"},
                    "confirm_ingest": {
                        "type": "boolean",
                        "description": "Must be true to confirm this write to Splunk HEC.",
                    },
                },
                "required": ["event", "confirm_ingest"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False},
        },
    },
    "veritas.ingest_demo_evidence": {
        "handler": tool_ingest_demo,
        "definition": {
            "name": "veritas.ingest_demo_evidence",
            "title": "Ingest Veritas Demo Evidence",
            "description": "Write the six Veritas admin-takeover evidence events to Splunk HEC. Use only with explicit human approval.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sample_file": {"type": "string"},
                    "incident_id": {"type": "string"},
                    "display_incident_id": {"type": "string"},
                    "index": {"type": "string"},
                    "sourcetype": {"type": "string"},
                    "confirm_ingest": {
                        "type": "boolean",
                        "description": "Must be true to confirm demo evidence ingestion through Splunk HEC.",
                    },
                },
                "required": ["confirm_ingest"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False},
        },
    },
}


def write_message(message):
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def response(message_id, result):
    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def error_response(message_id, code, message, data=None):
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": message_id, "error": error}


def handle_request(message):
    method = message.get("method")
    message_id = message.get("id")
    params = message.get("params") or {}

    if method == "initialize":
        return response(
            message_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": SERVER_NAME,
                    "title": SERVER_TITLE,
                    "version": APP_VERSION,
                },
                "instructions": (
                    "This server exposes real Splunk REST and HEC tools. It does not perform containment actions "
                    "and never returns configured tokens."
                ),
            },
        )

    if method == "ping":
        return response(message_id, {})

    if method == "tools/list":
        return response(message_id, {"tools": [item["definition"] for item in TOOLS.values()]})

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments") or {}
        tool = TOOLS.get(tool_name)
        if tool is None:
            return error_response(message_id, -32602, f"Unknown tool: {tool_name}")
        try:
            result = tool["handler"](arguments)
        except Exception as error:
            result = error_result(
                {
                    "provider": "splunk-mcp",
                    "tool": tool_name,
                    "error": str(error),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        return response(message_id, result)

    return error_response(message_id, -32601, f"Method not found: {method}")


def serve_stdio():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as error:
            write_message(error_response(None, -32700, "Parse error", {"error": str(error)}))
            continue

        if isinstance(message, list):
            write_message(error_response(None, -32600, "Batch messages are not supported"))
            continue

        if "id" not in message:
            if message.get("method") == "notifications/initialized":
                continue
            continue

        write_message(handle_request(message))


if __name__ == "__main__":
    serve_stdio()
