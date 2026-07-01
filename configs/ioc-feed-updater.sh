#!/bin/bash
# VN-SOC IOC feed updater — pull free URLhaus + AlienVault OTX daily.
# Runs via systemd timer daily 03:00. Writes into Logstash-readable format.
# Deploy: sudo cp to /opt/vnsoc-ioc/, chmod +x, systemd service/timer.

set -euo pipefail
IOC_DIR="/etc/logstash/ioc"
sudo mkdir -p "$IOC_DIR"

echo "[$(date -u +%FT%T)] Pulling URLhaus recent URLs..."
# URLhaus recent — CSV plain (bỏ zip vì service trả plain)
curl -sfL "https://urlhaus.abuse.ch/downloads/csv_recent/" \
  -o /tmp/urlhaus-recent.csv

# CSV format: id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
# All fields double-quoted, comma separator. Skip # comment lines.
grep -v '^#' /tmp/urlhaus-recent.csv | \
  awk -F'","' 'NF>=3 {print $3}' | \
  grep -v '^$' | \
  sort -u > /tmp/urlhaus-urls.txt

# Convert to Logstash translate dictionary YAML
python3 <<PYEOF > /tmp/urlhaus-dict.yml
lines = [l.strip() for l in open('/tmp/urlhaus-urls.txt') if l.strip()]
# Extract path only (Suricata http.url is path, not full URL)
paths = set()
for u in lines:
    try:
        from urllib.parse import urlparse
        p = urlparse(u).path
        if p and len(p) > 1:
            paths.add(p)
    except: pass
# YAML dict format for Logstash translate
for p in sorted(paths)[:5000]:  # cap 5000 for perf
    # Escape single quotes
    p_esc = p.replace("'", "''")
    print(f"'{p_esc}': 'urlhaus_recent'")
PYEOF

sudo mv /tmp/urlhaus-dict.yml "$IOC_DIR/urlhaus-paths.yml"
sudo chown root:logstash "$IOC_DIR/urlhaus-paths.yml"
sudo chmod 640 "$IOC_DIR/urlhaus-paths.yml"

TOTAL=$(wc -l < "$IOC_DIR/urlhaus-paths.yml")
echo "[$(date -u +%FT%T)] URLhaus paths loaded: $TOTAL"

# Trigger Logstash pipeline reload — refresh_interval trong translate filter tự handle
echo "[$(date -u +%FT%T)] IOC feed update complete."
