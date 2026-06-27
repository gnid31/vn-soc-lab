#!/usr/bin/env python3
"""Poll Kibana detection alerts → forward to n8n webhook.

Free-tier workaround vì Kibana basic license không có .webhook connector.
Chạy như systemd timer mỗi 30s. State (last-seen timestamp) ở /var/lib/vnsoc-soar/.
"""
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import requests

ES_URL = os.environ.get("ES_URL", "https://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ["ES_PASS"]
ALERTS_INDEX = os.environ.get("ALERTS_INDEX", ".internal.alerts-security.alerts-default-*")
N8N_WEBHOOK = os.environ.get("N8N_WEBHOOK", "http://127.0.0.1:5678/webhook/kibana-alert")
STATE_FILE = Path(os.environ.get("STATE_FILE", "/var/lib/vnsoc-soar/state.json"))
RULE_FILTER = os.environ.get("RULE_FILTER", "[VN-SOC ")  # tags prefix

STATE_FILE.parent.mkdir(parents=True, exist_ok=True)


def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"last_ts": (datetime.now(timezone.utc).isoformat())}


def save_state(state):
    STATE_FILE.write_text(json.dumps(state))


def fetch_alerts(since_iso):
    body = {
        "size": 100,
        "sort": [{"@timestamp": "asc"}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gt": since_iso}}},
                    {"prefix": {"kibana.alert.rule.name": RULE_FILTER}},
                ]
            }
        },
        "_source": [
            "@timestamp", "kibana.alert.rule.name", "kibana.alert.rule.uuid",
            "kibana.alert.severity", "kibana.alert.uuid",
            "url.original", "source.ip", "source.address",
            "user_agent.original", "ml",
        ],
    }
    r = requests.post(
        f"{ES_URL}/{ALERTS_INDEX}/_search",
        json=body,
        auth=(ES_USER, ES_PASS),
        verify=False,
        timeout=10,
    )
    r.raise_for_status()
    return r.json().get("hits", {}).get("hits", [])


def forward(hit):
    src = hit["_source"]
    payload = {
        "rule": {
            "name": src.get("kibana", {}).get("alert", {}).get("rule", {}).get("name") or
                    src.get("kibana.alert.rule.name", "unknown"),
            "severity": src.get("kibana", {}).get("alert", {}).get("severity") or
                        src.get("kibana.alert.severity", "medium"),
        },
        "url.original": src.get("url", {}).get("original") or src.get("url.original"),
        "source.ip": src.get("source", {}).get("ip") or src.get("source.ip") or
                     src.get("source", {}).get("address") or src.get("source.address"),
        "user_agent.original": src.get("user_agent", {}).get("original") or
                               src.get("user_agent.original"),
        "@timestamp": src["_source" in hit and "@timestamp"] if False else src.get("@timestamp"),
        "ml": src.get("ml", {}),
        "_alert_id": hit["_id"],
    }
    r = requests.post(N8N_WEBHOOK, json=payload, timeout=15)
    return r.status_code, r.text[:200]


def main():
    state = load_state()
    since = state["last_ts"]
    try:
        hits = fetch_alerts(since)
    except Exception as e:
        print(f"fetch error: {e}", file=sys.stderr)
        sys.exit(1)

    if not hits:
        print(f"no new alerts since {since}")
        return

    new_last = since
    forwarded = 0
    for h in hits:
        ts = h["_source"]["@timestamp"]
        try:
            code, resp = forward(h)
            if 200 <= code < 300:
                forwarded += 1
                new_last = ts
                print(f"  [OK {code}] {ts}  rule={h['_source'].get('kibana',{}).get('alert',{}).get('rule',{}).get('name','?')}")
            else:
                print(f"  [ERR {code}] {ts}  resp={resp}", file=sys.stderr)
                break
        except Exception as e:
            print(f"  [EXC] {ts}  {e}", file=sys.stderr)
            break

    if forwarded:
        state["last_ts"] = new_last
        save_state(state)
        print(f"forwarded {forwarded} alerts; last_ts={new_last}")


if __name__ == "__main__":
    main()
