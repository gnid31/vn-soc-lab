#!/bin/bash
# VN-SOC YARA scanner — scan critical paths on VPS + output NDJSON for Filebeat
# Deploy: /opt/vnsoc-yara/yara-scan.sh
# systemd timer trigger daily (or on-demand)

set -uo pipefail
# NOTE: -e removed — yara pipe reads to end trigger SIGPIPE causing spurious exit

RULES="/etc/yara/rules/vnsoc-malware-rules.yar"
LOG="/var/log/vnsoc-yara/scan.ndjson"
STATE="/var/lib/vnsoc-yara/lastscan.txt"

# Scan paths
SCAN_PATHS=(
    "/tmp"
    "/var/tmp"
    "/opt/vnsoc-ioc"
    "/opt/vnsoc-soar"
    "/var/www"
    "/root"
)
# Skip rules dir itself + IOC feed (self-referential noise)
SKIP_PATHS="/etc/yara /opt/vnsoc-yara /opt/vnsoc-ioc/*.yml /etc/logstash/ioc"
# NOTE: /home not scanned wholesale — node_modules + nvm cache noise. Restrict per-user.
# Exclude paths inside yara CLI: xem --exclude-dir=… (yara 4.x không native support, dùng find -not-path)

mkdir -p /var/log/vnsoc-yara /var/lib/vnsoc-yara
touch "$LOG"

TS=$(date -u +%FT%T.000Z)
HOSTNAME=$(hostname)
SCAN_ID=$(date +%s)

for path in "${SCAN_PATHS[@]}"; do
    if [ ! -d "$path" ] && [ ! -f "$path" ]; then continue; fi

    # -r recursive, -w suppress warnings, -N no follow symlinks (via manual dir walk)
    yara -r -w "$RULES" "$path" 2>/dev/null | while read -r line; do
        # Format: <RuleName> <FilePath>
        rule=$(echo "$line" | awk '{print $1}')
        filepath=$(echo "$line" | sed "s|^$rule ||")

        [ -z "$rule" ] && continue

        # Get file metadata
        size=$(stat -c %s "$filepath" 2>/dev/null || echo 0)
        sha256=$(sha256sum "$filepath" 2>/dev/null | awk '{print $1}' || echo "")

        # Extract rule severity/mitre từ .yar file (grep meta)
        severity=$(awk -v r="$rule" '$0 ~ "rule "r"$" || $0 ~ "rule "r"[ {]" {flag=1} flag && /severity/{gsub(/.*= *"?/,""); gsub(/"?$/,""); print; exit}' "$RULES" 2>/dev/null || echo "unknown")

        # Emit NDJSON
        jq -c -n \
            --arg ts "$TS" \
            --arg host "$HOSTNAME" \
            --arg scan_id "$SCAN_ID" \
            --arg path "$filepath" \
            --arg rule "$rule" \
            --arg sev "$severity" \
            --arg sha "$sha256" \
            --argjson size "$size" \
            '{
                "@timestamp": $ts,
                "host": {"name": $host},
                "yara": {
                    "scan_id": $scan_id,
                    "rule": $rule,
                    "severity": $sev
                },
                "file": {
                    "path": $path,
                    "size": $size,
                    "hash": {"sha256": $sha}
                },
                "event": {
                    "category": "malware",
                    "module": "yara",
                    "action": "yara_match",
                    "dataset": "yara.scan"
                },
                "tags": ["yara", "malware-scan"]
            }' >> "$LOG"
    done
done

echo "$TS" > "$STATE"
echo "[$TS] YARA scan complete on ${HOSTNAME}"
