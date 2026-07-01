#!/bin/bash
# VN-SOC Trivy scanner — Docker images + filesystem paths.
# Deploy: /opt/vnsoc-vuln/trivy-scan.sh
# systemd timer daily 02:30.
#
# Output: /var/log/vnsoc-vuln/trivy-*.ndjson (1 file per scan)
# NDJSON fields: @timestamp, host.name, vuln.{cve,severity,pkg,target}, file.path

set -uo pipefail
# NOTE: -e omitted vì trivy exit non-zero khi có vuln found — expected

OUT_DIR="/var/log/vnsoc-vuln"
mkdir -p "$OUT_DIR"
TS=$(date -u +%FT%T.000Z)
HOSTNAME=$(hostname)
SCAN_ID=$(date +%s)
LOG="$OUT_DIR/trivy-$(date +%Y%m%d-%H%M%S).ndjson"

emit_finding() {
    local target="$1" cve="$2" severity="$3" pkg="$4" installed="$5" fixed="$6" title="$7"
    jq -c -n \
        --arg ts "$TS" \
        --arg host "$HOSTNAME" \
        --arg scan_id "$SCAN_ID" \
        --arg target "$target" \
        --arg cve "$cve" \
        --arg sev "$severity" \
        --arg pkg "$pkg" \
        --arg inst "$installed" \
        --arg fix "$fixed" \
        --arg title "$title" \
        '{
            "@timestamp": $ts,
            "host": {"name": $host},
            "vuln": {
                "scan_id": $scan_id,
                "scanner": "trivy",
                "target": $target,
                "cve": $cve,
                "severity": $sev,
                "package": $pkg,
                "installed_version": $inst,
                "fixed_version": $fix,
                "title": $title
            },
            "event": {
                "category": "vulnerability",
                "module": "trivy",
                "action": "vuln_found",
                "dataset": "trivy.scan"
            },
            "tags": ["trivy", "vulnerability", "scan"]
        }' >> "$LOG"
}

scan_target() {
    local target_type="$1"     # image | fs
    local target="$2"
    echo "[$(date -u +%FT%T)] Scanning $target_type: $target"

    trivy "$target_type" \
        --quiet \
        --format json \
        --severity HIGH,CRITICAL \
        --ignore-unfixed=false \
        --scanners vuln \
        --timeout 5m \
        "$target" 2>/dev/null > /tmp/trivy-tmp.json || true

    [ ! -s /tmp/trivy-tmp.json ] && return

    # Parse Trivy JSON output — extract Results[].Vulnerabilities[]
    python3 <<PYEOF >> "$LOG" 2>/dev/null
import json, sys
try:
    d = json.load(open('/tmp/trivy-tmp.json'))
    for r in d.get('Results', []) or []:
        for v in r.get('Vulnerabilities', []) or []:
            out = {
                "@timestamp": "$TS",
                "host": {"name": "$HOSTNAME"},
                "vuln": {
                    "scan_id": "$SCAN_ID",
                    "scanner": "trivy",
                    "target": "$target",
                    "target_type": "$target_type",
                    "cve": v.get('VulnerabilityID'),
                    "severity": v.get('Severity'),
                    "package": v.get('PkgName'),
                    "installed_version": v.get('InstalledVersion'),
                    "fixed_version": v.get('FixedVersion', ''),
                    "title": (v.get('Title') or '')[:200],
                    "primary_url": v.get('PrimaryURL', '')
                },
                "event": {
                    "category": "vulnerability",
                    "module": "trivy",
                    "action": "vuln_found",
                    "dataset": "trivy.scan"
                },
                "tags": ["trivy", "vulnerability", "scan"]
            }
            print(json.dumps(out))
except Exception as e:
    print(f'Parse error: {e}', file=sys.stderr)
PYEOF
}

# Docker images to scan
if command -v docker >/dev/null; then
    docker images --format '{{.Repository}}:{{.Tag}}' | grep -v '<none>' | sort -u | while read -r img; do
        [ -z "$img" ] && continue
        scan_target image "$img"
    done
fi

# Filesystem paths
for fspath in "/opt/vnsoc-soar" "/opt/vnsoc-ioc" "/opt/vnsoc-yara" "/opt/vnsoc-ueba" "/etc/logstash" "/etc/kibana" "/etc/elasticsearch"; do
    [ -d "$fspath" ] && scan_target fs "$fspath"
done

FINDINGS=$(wc -l < "$LOG" 2>/dev/null || echo 0)
echo "[$(date -u +%FT%T)] Trivy scan complete — $FINDINGS findings → $LOG"
