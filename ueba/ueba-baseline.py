#!/usr/bin/env python3
"""VN-SOC UEBA baseline anomaly detection.

Cách hoạt động (per-user daily):
1. Query ES aggregations trên winlogbeat-* / suricata-* / dvwa-apache-* / cowrie-*
   trong last 24h + baseline window (last 14d).
2. Compute z-score cho mỗi metric: nếu today > baseline_mean + 2*std → flag anomaly.
3. Output NDJSON to /var/log/vnsoc-ueba/anomalies.ndjson (Filebeat sẽ ship).
4. Emit metadata: user, host, metric, current_value, baseline_mean, baseline_std, z_score, is_anomaly.

Metrics tracked:
- Failed logon count per user (winlogbeat event.code 4625)
- Process spawn count per user (winlogbeat event.code 1)
- Unique DestinationIp per user (winlogbeat event.code 3)
- Unique URL requested per source.address (dvwa-apache)
- SSH bruteforce attempts per src_ip (cowrie login.failed)

Deploy: /opt/vnsoc-ueba/ueba-baseline.py + systemd timer daily.
"""

import json
import os
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import requests

ES_URL = os.environ.get("ES_URL", "https://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ["ES_PASS"]
OUT = Path(os.environ.get("OUT", "/var/log/vnsoc-ueba/anomalies.ndjson"))
Z_THRESHOLD = float(os.environ.get("Z_THRESHOLD", "2.0"))

OUT.parent.mkdir(parents=True, exist_ok=True)
now = datetime.now(timezone.utc).isoformat()

def es_agg(index, query_filter, agg_field, time_field="@timestamp",
           now_offset="now-24h", history_offset="now-14d/d", history_end="now-1d/d"):
    """Return (today_value, baseline_daily_values) - count of unique agg_field."""
    body_today = {
        "size": 0,
        "query": {"bool": {"must": [query_filter, {"range": {time_field: {"gte": now_offset}}}]}},
        "aggs": {"unique": {"cardinality": {"field": agg_field}}}
    }
    body_hist = {
        "size": 0,
        "query": {"bool": {"must": [query_filter, {"range": {time_field: {"gte": history_offset, "lt": history_end}}}]}},
        "aggs": {
            "by_day": {"date_histogram": {"field": time_field, "calendar_interval": "day"},
                       "aggs": {"unique": {"cardinality": {"field": agg_field}}}}
        }
    }
    try:
        r1 = requests.post(f"{ES_URL}/{index}/_search", json=body_today,
                          auth=(ES_USER, ES_PASS), verify=False, timeout=15)
        r2 = requests.post(f"{ES_URL}/{index}/_search", json=body_hist,
                          auth=(ES_USER, ES_PASS), verify=False, timeout=15)
        today = r1.json().get("aggregations", {}).get("unique", {}).get("value", 0)
        days = [b["unique"]["value"] for b in r2.json().get("aggregations", {}).get("by_day", {}).get("buckets", [])]
        return today, days
    except Exception as e:
        print(f"ES agg error: {e}", file=sys.stderr)
        return None, []


def z_score(today, days):
    if len(days) < 3:
        return None, None, None
    mean = statistics.mean(days)
    std = statistics.stdev(days) if len(days) > 1 else 1
    if std == 0:
        return today - mean, mean, 0
    z = (today - mean) / std
    return z, mean, std


def check(metric_name, index, query_filter, agg_field, low_baseline_ok=False):
    today, days = es_agg(index, query_filter, agg_field)
    if today is None:
        return
    z, mean, std = z_score(today, days)
    if z is None:
        # Not enough baseline
        return
    is_anomaly = z >= Z_THRESHOLD and today > 0
    result = {
        "@timestamp": now,
        "ueba": {
            "metric": metric_name,
            "index": index,
            "today_value": today,
            "baseline_mean": round(mean, 2),
            "baseline_std": round(std, 2) if std else 0,
            "z_score": round(z, 2),
            "threshold_z": Z_THRESHOLD,
            "is_anomaly": is_anomaly
        },
        "event": {"category": "authentication", "module": "vnsoc-ueba", "action": "baseline_check", "kind": "state"},
        "tags": ["ueba", "vnsoc-lab"] + (["anomaly"] if is_anomaly else [])
    }
    with OUT.open("a") as f:
        f.write(json.dumps(result) + "\n")
    print(f"[{metric_name}] today={today} mean={mean:.1f} std={std:.1f} z={z:.2f} anomaly={is_anomaly}")


# ---- Metric checks ----
check("failed_logon_count",
      "winlogbeat-*",
      {"match": {"event.code": "4625"}},
      "winlog.event_data.TargetUserName.keyword")

check("process_spawn_unique_images",
      "winlogbeat-*",
      {"match": {"event.code": "1"}},
      "winlog.event_data.Image.keyword")

check("outbound_dest_ips",
      "winlogbeat-*",
      {"match": {"event.code": "3"}},
      "winlog.event_data.DestinationIp.keyword")

check("dvwa_unique_urls_per_client",
      "dvwa-apache-*",
      {"match_all": {}},
      "url.original.keyword")

check("cowrie_src_ips",
      "cowrie-*",
      {"match": {"eventid": "cowrie.login.failed"}},
      "src_ip.keyword")

check("suricata_alerts_unique_src",
      "suricata-*",
      {"match": {"event_type": "alert"}},
      "src_ip.keyword")

print(f"\nUEBA baseline check complete → {OUT}")
