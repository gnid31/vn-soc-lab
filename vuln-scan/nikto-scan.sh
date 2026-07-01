#!/bin/bash
# VN-SOC Nikto scanner — web attack surface probe.
# Deploy: /opt/vnsoc-vuln/nikto-scan.sh
# systemd timer weekly Sunday 03:00.
#
# Output: /var/log/vnsoc-vuln/nikto-*.ndjson

set -uo pipefail

OUT_DIR="/var/log/vnsoc-vuln"
mkdir -p "$OUT_DIR"
TS=$(date -u +%FT%T.000Z)
HOSTNAME=$(hostname)
SCAN_ID=$(date +%s)
LOG="$OUT_DIR/nikto-$(date +%Y%m%d-%H%M%S).ndjson"

TARGETS=(
    "http://127.0.0.1:5601"                    # Kibana
    "http://192.168.154.165:8080"              # DVWA (SOC-Tools) — nếu VM on
)

for target in "${TARGETS[@]}"; do
    echo "[$(date -u +%FT%T)] Nikto scanning $target"

    # Quick reachability
    if ! curl -sf --connect-timeout 5 "$target" -o /dev/null 2>&1; then
        echo "  → unreachable, skip"
        continue
    fi

    # Nikto CSV format (-Format csv) parseable
    nikto -h "$target" \
        -Format csv \
        -output /tmp/nikto-tmp.csv \
        -Tuning 123456789 \
        -maxtime 3m \
        -nointeractive 2>&1 | tail -3

    # Parse CSV → NDJSON
    python3 <<PYEOF >> "$LOG" 2>/dev/null
import csv, json, sys
try:
    with open('/tmp/nikto-tmp.csv') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 7: continue
            hostname_col, ip_col, port_col, osvdb_col, method_col, uri_col, desc_col = row[:7]
            if not uri_col and not desc_col: continue
            # Severity heuristic: OSVDB present or "SQL injection" / "XSS" / "shell" in desc → HIGH
            desc_lower = desc_col.lower()
            if any(k in desc_lower for k in ('sql injection', 'xss', 'remote code', 'shell', 'directory listing', 'authentication bypass')):
                sev = 'HIGH'
            elif any(k in desc_lower for k in ('information disclosure', 'server header', 'apache version')):
                sev = 'LOW'
            elif osvdb_col and osvdb_col != '0':
                sev = 'MEDIUM'
            else:
                sev = 'INFO'
            out = {
                "@timestamp": "$TS",
                "host": {"name": "$HOSTNAME"},
                "vuln": {
                    "scan_id": "$SCAN_ID",
                    "scanner": "nikto",
                    "target": "$target",
                    "target_ip": ip_col,
                    "target_port": port_col,
                    "cve": f"OSVDB-{osvdb_col}" if osvdb_col and osvdb_col != "0" else "",
                    "severity": sev,
                    "method": method_col,
                    "uri": uri_col,
                    "description": desc_col[:300]
                },
                "event": {
                    "category": "vulnerability",
                    "module": "nikto",
                    "action": "web_probe",
                    "dataset": "nikto.scan"
                },
                "tags": ["nikto", "vulnerability", "web-scan"]
            }
            print(json.dumps(out))
except Exception as e:
    print(f'Parse error: {e}', file=sys.stderr)
PYEOF
done

FINDINGS=$(wc -l < "$LOG" 2>/dev/null || echo 0)
echo "[$(date -u +%FT%T)] Nikto scan complete — $FINDINGS findings → $LOG"
