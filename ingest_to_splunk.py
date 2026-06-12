import argparse
import json
import os
import ssl
import time
from urllib import request

from server import ATTACK_EVENTS, VERITAS_INCIDENT_ID, VERITAS_SOURCETYPE, VERITAS_SPLUNK_INDEX

ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SAMPLE_FILE = os.path.join(ROOT, "sample_splunk_events.json")


def env_bool(name, default=True):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() not in {"0", "false", "no"}


def source_category(event):
    return event["source"].replace("splunk:index=", "")


def normalize_hec_url(hec_url):
    cleaned = hec_url.rstrip("/")
    if cleaned.endswith("/services/collector"):
        return f"{cleaned}/event"
    return cleaned


def hec_context(verify_ssl):
    if verify_ssl:
        return None
    return ssl._create_unverified_context()


def load_events(path):
    if not os.path.exists(path):
        return ATTACK_EVENTS
    with open(path, "r", encoding="utf-8") as handle:
        events = json.load(handle)
    if not isinstance(events, list):
        raise ValueError(f"{path} must contain a JSON array of events")
    return events


def event_value(event, key, default=None):
    value = event.get(key, default)
    return value if value is not None else default


def hec_event(event, index, incident_id, display_incident_id, sourcetype, timestamp):
    body = {
        "time": timestamp,
        "host": "veritas-demo",
        "source": "veritas-ai",
        "sourcetype": sourcetype,
        "index": index,
        "event": {
            "incident_id": incident_id,
            "display_incident_id": display_incident_id,
            "event_id": event_value(event, "event_id", event.get("id")),
            "source_category": source_category(event),
            "event_type": event_value(event, "event_type", source_category(event)),
            "summary": event["summary"],
            "message": event_value(event, "message", event["summary"]),
            "user": event_value(event, "user", ""),
            "src_ip": event_value(event, "src_ip", ""),
            "geo": event_value(event, "geo", ""),
            "action": event_value(event, "action", ""),
            "severity": event_value(event, "severity", "info"),
            "query": event["query"],
            "tags": event_value(event, "tags", []),
            "evidence_category": event_value(event, "evidence_category", source_category(event)),
            "demo_time": event_value(event, "time", ""),
        },
    }
    return body


def send_hec_event(hec_url, token, payload, verify_ssl):
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        hec_url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        },
    )
    with request.urlopen(req, timeout=10, context=hec_context(verify_ssl)) as response:
        return json.loads(response.read().decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Ingest Veritas demo evidence into Splunk HEC.")
    parser.add_argument("--hec-url", default=os.environ.get("SPLUNK_HEC_URL", ""))
    parser.add_argument("--token", default=os.environ.get("SPLUNK_HEC_TOKEN") or os.environ.get("SPLUNK_TOKEN", ""))
    parser.add_argument("--index", default=os.environ.get("VERITAS_SPLUNK_INDEX", VERITAS_SPLUNK_INDEX))
    parser.add_argument("--incident-id", default=os.environ.get("VERITAS_INCIDENT_ID", VERITAS_INCIDENT_ID))
    parser.add_argument("--display-incident-id", default=os.environ.get("VERITAS_DISPLAY_INCIDENT_ID", "INC-2025-0001"))
    parser.add_argument("--sourcetype", default=os.environ.get("VERITAS_SOURCETYPE", VERITAS_SOURCETYPE))
    parser.add_argument("--verify-ssl", default=os.environ.get("SPLUNK_VERIFY_SSL", "true"))
    parser.add_argument("--sample-file", default=os.environ.get("VERITAS_SAMPLE_FILE", DEFAULT_SAMPLE_FILE))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    verify_ssl = args.verify_ssl.lower() not in {"0", "false", "no"}
    if not args.hec_url and not args.dry_run:
        raise SystemExit("Missing HEC URL. Set SPLUNK_HEC_URL, for example https://Cyberrockng:8088/services/collector")
    if not args.token and not args.dry_run:
        raise SystemExit("Missing HEC token. Set SPLUNK_HEC_TOKEN.")

    events = load_events(args.sample_file)
    start_time = time.time() - 300
    payloads = [
        hec_event(
            event,
            args.index,
            args.incident_id,
            args.display_incident_id,
            args.sourcetype,
            start_time + offset,
        )
        for offset, event in enumerate(events)
    ]

    if args.dry_run:
        print(json.dumps(payloads, indent=2))
        return

    hec_url = normalize_hec_url(args.hec_url)
    successes = 0
    failures = []
    for payload in payloads:
        event_id = payload["event"]["event_id"]
        try:
            result = send_hec_event(hec_url, args.token, payload, verify_ssl)
        except Exception as error:
            failures.append((event_id, str(error)))
            print(f"{event_id}: failed")
            continue
        if result.get("code") == 0:
            successes += 1
        else:
            failures.append((event_id, json.dumps(result)))
        event_id = payload["event"]["event_id"]
        print(f"{event_id}: {'success' if result.get('code') == 0 else 'failed'}")

    if failures:
        print(f"HEC ingestion failed for {len(failures)} of {len(payloads)} events.")
        for event_id, reason in failures:
            print(f"- {event_id}: {reason}")
        raise SystemExit(1)

    print(f"Ingested {successes} Veritas evidence events into Splunk index={args.index}")


if __name__ == "__main__":
    main()
