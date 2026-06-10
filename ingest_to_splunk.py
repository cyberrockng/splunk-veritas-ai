import argparse
import json
import os
import ssl
import time
from urllib import request

from server import ATTACK_EVENTS, VERITAS_INCIDENT_ID, VERITAS_SOURCETYPE, VERITAS_SPLUNK_INDEX


def env_bool(name, default=True):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() not in {"0", "false", "no"}


def source_category(event):
    return event["source"].replace("splunk:index=", "")


def hec_context(verify_ssl):
    if verify_ssl:
        return None
    return ssl._create_unverified_context()


def hec_event(event, index, incident_id, sourcetype, timestamp):
    body = {
        "time": timestamp,
        "host": "veritas-demo",
        "source": "veritas-ai",
        "sourcetype": sourcetype,
        "index": index,
        "event": {
            "incident_id": incident_id,
            "event_id": event["id"],
            "source_category": source_category(event),
            "summary": event["summary"],
            "user": event["user"],
            "src_ip": event["src_ip"],
            "geo": event["geo"],
            "severity": event["severity"],
            "query": event["query"],
            "tags": event["tags"],
            "demo_time": event["time"],
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
    parser.add_argument("--sourcetype", default=os.environ.get("VERITAS_SOURCETYPE", VERITAS_SOURCETYPE))
    parser.add_argument("--verify-ssl", default=os.environ.get("SPLUNK_VERIFY_SSL", "true"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    verify_ssl = args.verify_ssl.lower() not in {"0", "false", "no"}
    if not args.hec_url and not args.dry_run:
        raise SystemExit("Missing HEC URL. Set SPLUNK_HEC_URL, for example https://localhost:8088/services/collector/event")
    if not args.token and not args.dry_run:
        raise SystemExit("Missing HEC token. Set SPLUNK_HEC_TOKEN.")

    start_time = time.time() - 300
    payloads = [
        hec_event(
            event,
            args.index,
            args.incident_id,
            args.sourcetype,
            start_time + offset,
        )
        for offset, event in enumerate(ATTACK_EVENTS)
    ]

    if args.dry_run:
        print(json.dumps(payloads, indent=2))
        return

    for payload in payloads:
        result = send_hec_event(args.hec_url, args.token, payload, verify_ssl)
        event_id = payload["event"]["event_id"]
        print(f"{event_id}: {result}")

    print(
        "Ingested "
        f"{len(payloads)} events into index={args.index}, sourcetype={args.sourcetype}, "
        f"incident_id={args.incident_id}."
    )


if __name__ == "__main__":
    main()
