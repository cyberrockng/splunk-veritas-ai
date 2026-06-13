import argparse
import json
import os
import sys
import time
from urllib import request

from server import VERITAS_INCIDENT_ID, VERITAS_SOURCETYPE, VERITAS_SPLUNK_INDEX

ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MANIFEST = os.path.join(ROOT, "external_feed_sources.json")
DEFAULT_OUTPUT = os.path.join(ROOT, "external_veritas_events.json")
GIT_LFS_BATCH_URL = "https://github.com/splunk/attack_data.git/info/lfs/objects/batch"


def read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def request_bytes(url, data=None, headers=None, method=None):
    req = request.Request(
        url,
        data=data,
        headers={
            "User-Agent": "Veritas-AI-external-feed/1.0",
            **(headers or {}),
        },
        method=method,
    )
    with request.urlopen(req, timeout=30) as response:
        return response.read()


def lfs_download(oid, size):
    body = json.dumps(
        {
            "operation": "download",
            "transfers": ["basic"],
            "objects": [{"oid": oid, "size": size}],
        }
    ).encode("utf-8")
    response = json.loads(
        request_bytes(
            GIT_LFS_BATCH_URL,
            data=body,
            headers={
                "Accept": "application/vnd.git-lfs+json",
                "Content-Type": "application/vnd.git-lfs+json",
            },
            method="POST",
        ).decode("utf-8")
    )
    obj = response["objects"][0]
    if "error" in obj:
        raise RuntimeError(f"Git LFS download refused for {oid}: {obj['error']}")
    return request_bytes(obj["actions"]["download"]["href"]).decode("utf-8", errors="replace")


def fetch_source(source):
    raw = request_bytes(source["raw_url"]).decode("utf-8", errors="replace")
    if raw.startswith("version https://git-lfs.github.com/spec/v1"):
        lfs = source.get("git_lfs")
        if not lfs:
            raise RuntimeError(f"{source['id']} is a Git LFS pointer but has no git_lfs metadata")
        return lfs_download(lfs["oid"], lfs["size"])
    return raw


def parse_json_lines(text):
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def first_non_empty(*values):
    for value in values:
        if value not in (None, ""):
            return value
    return ""


def actor_email(row):
    actor = row.get("actor") or row.get("Actor")
    if isinstance(actor, dict):
        return first_non_empty(actor.get("alternateId"), actor.get("displayName"), actor.get("id"))
    if isinstance(actor, list):
        for item in actor:
            value = item.get("ID") if isinstance(item, dict) else None
            if isinstance(value, str) and "@" in value:
                return value
    return first_non_empty(row.get("UserId"), row.get("user"), row.get("UserKey"))


def okta_event(rows, source):
    row = rows[0]
    client = row.get("client", {})
    debug = row.get("debugContext", {}).get("debugData", {})
    src_ip = first_non_empty(
        client.get("ipAddress"),
        debug.get("suspiciousActivityEventIp"),
        row.get("client", {}).get("ipAddress"),
    )
    city = client.get("geographicalContext", {}).get("city")
    country = client.get("geographicalContext", {}).get("country")
    location = ", ".join(part for part in [city, country] if part)
    event_type = row.get("eventType", "okta_suspicious_activity")
    return {
        "id": "SEC-3001",
        "source": "splunk:index=identity",
        "query": 'index=veritas sourcetype="veritas:incident" event_id=SEC-3001',
        "summary": f"Okta suspicious activity reported by end user: {event_type}.",
        "message": row.get("displayMessage") or event_type,
        "event_type": "suspicious_login_source",
        "evidence_category": "identity",
        "user": actor_email(row),
        "src_ip": src_ip,
        "geo": location,
        "action": event_type,
        "severity": "high",
        "tags": ["identity", "okta", "public-attack-data", source["technique"]],
        "source_dataset": source["id"],
        "source_url": source["raw_url"],
        "upstream_timestamp": row.get("published"),
    }


def sso_event(rows, source):
    parsed = [row.get("result", row) for row in rows]
    ips = sorted({row.get("ActorIpAddress") for row in parsed if row.get("ActorIpAddress")})
    errors = sorted({row.get("LogonError") for row in parsed if row.get("LogonError")})
    user_agents = sorted({row.get("UserAgent") for row in parsed if row.get("UserAgent")})
    return {
        "id": "SEC-3002",
        "source": "splunk:index=identity",
        "query": 'index=veritas sourcetype="veritas:incident" event_id=SEC-3002',
        "summary": f"O365 excessive SSO failures observed: {len(parsed)} failures across {len(ips)} source IPs.",
        "message": f"Observed {', '.join(errors) or 'SSO errors'} from {', '.join(ips) or 'unknown IPs'}.",
        "event_type": "mfa_or_sso_anomaly",
        "evidence_category": "mfa",
        "user": "unknown",
        "src_ip": ips[0] if ips else "",
        "geo": "",
        "action": "sso_failure_burst",
        "severity": "high",
        "tags": ["mfa", "sso", "o365", "public-attack-data", source["technique"]],
        "source_dataset": source["id"],
        "source_url": source["raw_url"],
        "observed_count": len(parsed),
        "distinct_source_ips": ips,
        "user_agents": user_agents[:3],
    }


def workload_events(rows, source):
    role_change = next((row for row in rows if row.get("Operation") == "Add member to role."), rows[0])
    admin_change = next(
        (
            row
            for row in rows
            if row.get("Operation") in {"Update policy.", "Add application.", "Update application."}
        ),
        rows[min(1, len(rows) - 1)],
    )
    events = []
    for event_id, row, category, event_type, action, summary in [
        (
            "SEC-3003",
            role_change,
            "iam",
            "privilege_escalation",
            "role_change",
            "Azure AD privileged account manipulation observed in workload audit data.",
        ),
        (
            "SEC-3004",
            admin_change,
            "api",
            "admin_control_plane_change",
            "admin_workload_change",
            "O365/Azure control-plane change observed during account manipulation activity.",
        ),
    ]:
        events.append(
            {
                "id": event_id,
                "source": f"splunk:index={category}",
                "query": f'index=veritas sourcetype="veritas:incident" event_id={event_id}',
                "summary": summary,
                "message": f"{row.get('Operation', 'Workload event')} against {row.get('ObjectId', 'unknown object')}.",
                "event_type": event_type,
                "evidence_category": category,
                "user": actor_email(row),
                "src_ip": first_non_empty(row.get("ClientIP"), row.get("ActorIpAddress")),
                "geo": "",
                "action": action,
                "severity": "critical",
                "tags": ["azure-ad", "o365", "public-attack-data", source["technique"]],
                "source_dataset": source["id"],
                "source_url": source["raw_url"],
                "upstream_timestamp": row.get("CreationTime"),
                "upstream_operation": row.get("Operation"),
                "upstream_object": row.get("ObjectId"),
            }
        )
    return events


def normalize_sources(manifest):
    normalized = []
    fetched = []
    for source in manifest["sources"]:
        text = fetch_source(source)
        rows = parse_json_lines(text)
        fetched.append({"id": source["id"], "rows": len(rows)})
        if source["id"].endswith("okta-suspicious-activity"):
            normalized.append(okta_event(rows, source))
        elif source["id"].endswith("o365-excessive-sso-errors"):
            normalized.append(sso_event(rows, source))
        elif source["id"].endswith("o365-azure-workload-events"):
            normalized.extend(workload_events(rows, source))
    return normalized, fetched


def hec_payload(event, args, timestamp):
    source_category = event["source"].replace("splunk:index=", "")
    return {
        "time": timestamp,
        "host": "veritas-external-feed",
        "source": "splunk-attack-data-online",
        "sourcetype": args.sourcetype,
        "index": args.index,
        "event": {
            "incident_id": args.incident_id,
            "display_incident_id": args.display_incident_id,
            "event_id": event["id"],
            "source_category": source_category,
            "event_type": event["event_type"],
            "summary": event["summary"],
            "message": event["message"],
            "user": event.get("user", ""),
            "src_ip": event.get("src_ip", ""),
            "geo": event.get("geo", ""),
            "action": event.get("action", ""),
            "severity": event.get("severity", "info"),
            "query": event["query"],
            "tags": event.get("tags", []),
            "evidence_category": event.get("evidence_category", source_category),
            "source_dataset": event.get("source_dataset", ""),
            "source_url": event.get("source_url", ""),
            "upstream_timestamp": event.get("upstream_timestamp", ""),
            "upstream_operation": event.get("upstream_operation", ""),
            "upstream_object": event.get("upstream_object", ""),
        },
    }


def build_payloads(events, args):
    start_time = time.time() - 300
    return [hec_payload(event, args, start_time + offset) for offset, event in enumerate(events)]


def main():
    parser = argparse.ArgumentParser(description="Fetch online attack-data sources and convert them to Veritas evidence events.")
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--incident-id", default=os.environ.get("VERITAS_INCIDENT_ID", VERITAS_INCIDENT_ID))
    parser.add_argument("--display-incident-id", default=os.environ.get("VERITAS_DISPLAY_INCIDENT_ID", "INC-2025-0001"))
    parser.add_argument("--index", default=os.environ.get("VERITAS_SPLUNK_INDEX", VERITAS_SPLUNK_INDEX))
    parser.add_argument("--sourcetype", default=os.environ.get("VERITAS_SOURCETYPE", VERITAS_SOURCETYPE))
    parser.add_argument("--hec-payload", action="store_true", help="Write Splunk HEC payloads instead of plain Veritas events.")
    parser.add_argument("--stdout", action="store_true", help="Print generated data instead of writing a file.")
    args = parser.parse_args()

    manifest = read_json(args.manifest)
    events, fetched = normalize_sources(manifest)
    output = build_payloads(events, args) if args.hec_payload else events

    if args.stdout:
        print(json.dumps(output, indent=2))
    else:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(output, handle, indent=2)
            handle.write("\n")

    summary = {
        "sources_fetched": fetched,
        "events_ready": [event["id"] for event in events],
        "output": "stdout" if args.stdout else args.output,
        "format": "splunk-hec-payload" if args.hec_payload else "veritas-event-list",
    }
    print(json.dumps(summary, indent=2), file=sys.stderr)


if __name__ == "__main__":
    main()
