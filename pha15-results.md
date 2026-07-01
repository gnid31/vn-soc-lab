# Pha 15 — Vulnerability Management (Trivy + Nikto)

> Continuous vulnerability scanning layer — Trivy daily scan Docker images +
> filesystem (CVE + IaC + secrets + SBOM), Nikto weekly web endpoint probe.
> Results → ES → R18 detection rule fire on HIGH/CRITICAL → TheHive triage case
> auto-created via existing SOAR bridge. Complement detection engineering với
> "know your attack surface" story.

**Ngày thực hiện:** 2026-07-01
**Thời gian:** ~1 giờ (deploy + smoke-test + docs)
**Hardware change:** None; +2 systemd timers + 2 scanner CLI binaries

---

## 1. Tóm tắt

Detection engineering only covers "what attacker DOES" (Pha 3-14). Pha 15 add "what attacker COULD DO" — track own attack surface qua CVE + web vuln scan.

- **Trivy 0.72.0** — Docker image + filesystem vulnerability scanner. Single Go binary, offline DB. Scan cả 3 layer: OS packages, application dependencies, IaC/secrets/misconfig.
- **Nikto 2.5** — Web application security scanner. CSV output parseable. Scan HTTP endpoints (Kibana + DVWA).
- **NDJSON output** — 2 scanner emit chuẩn format → Filebeat filestream → Logstash branch `vnsoc-vuln` → index `vuln-scan-*`.
- **systemd timer**: Trivy daily 02:30, Nikto weekly Sunday 03:00.
- **R18 detection rule**: fire on `vuln.severity : (CRITICAL OR HIGH)` → auto SOAR case.
- **Smoke-test verified**: 768 CVE findings (679 HIGH + 89 CRITICAL) từ 5 Docker images + 4 filesystem paths → indexed → R18 fired.

---

## 2. Architecture

```
VPS 43.228.215.234:
  ├─ Trivy 0.72 CLI (/usr/local/bin/trivy)
  │   ├─ scan targets:
  │   │   • Docker images running (via `docker images` list)
  │   │     - ml-url-api:latest, n8n:1.74.1, cowrie:latest, +user containers
  │   │   • Filesystem paths:
  │   │     - /opt/vnsoc-{soar,ioc,yara,ueba} (custom code)
  │   │     - /etc/{logstash,kibana,elasticsearch} (stack config)
  │   ├─ severity filter: HIGH + CRITICAL (skip LOW/MEDIUM noise)
  │   └─ output: /var/log/vnsoc-vuln/trivy-<ts>.ndjson
  │
  ├─ Nikto 2.5 CLI (/usr/bin/nikto)
  │   ├─ scan targets:
  │   │   • http://127.0.0.1:5601 (Kibana attack surface)
  │   │   • http://192.168.154.165:8080 (DVWA when SOC-Tools online)
  │   └─ output: /var/log/vnsoc-vuln/nikto-<ts>.ndjson (parsed từ CSV)
  │
  ├─ Filebeat 8.19 (existing, +1 filestream input)
  │   /var/log/vnsoc-vuln/{trivy,nikto}-*.ndjson → :5044 tag source_type=vnsoc-vuln
  │
  ├─ Logstash new branch
  │   filter add_tag [vuln, vulnerability, scan] + event.category vulnerability
  │   output index vuln-scan-YYYY.MM.dd, ILM policy vnsoc-30d applied
  │
  ├─ systemd timers
  │   vnsoc-trivy.timer  daily 02:30, RandomizedDelaySec 30m
  │   vnsoc-nikto.timer  weekly Sun 03:00, RandomizedDelaySec 30m
  │
  └─ Kibana R18 detection rule
      Query: vuln.severity : (CRITICAL OR HIGH) AND event.module : (trivy OR nikto)
      Schedule: 30m interval, look-back 2h
```

---

## 3. Setup stages

> **Dual-path convention:** Stages 3.1-3.4 (install tool + write scan script + Logstash pipeline + systemd) là **CLI-only** — configs file-based. Stage 3.5 (Kibana R18) có GUI via Detection Engine UI + CLI qua REST API.

### 3.1 Install Trivy + Nikto (CLI-only)

**Nikto** — apt package:
```bash
sudo apt install -y nikto
nikto -Version  # → Nikto v2.5.0
```

**Trivy** — official install script (Aquasec):
```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | \
  sudo sh -s -- -b /usr/local/bin
trivy --version  # → Version: 0.72.0
```

Alternative: Trivy deb repo cho apt-update workflow:
```bash
sudo apt install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt update && sudo apt install trivy
```

### 3.2 Scan scripts

**`vuln-scan/trivy-scan.sh`** (CLI-only):
- Iterate `docker images` list → scan mỗi image
- Iterate hardcoded filesystem paths → scan mỗi dir
- Trivy JSON output → Python parse → NDJSON append với fields `vuln.{cve, severity, package, target, installed_version, fixed_version, primary_url}`

**`vuln-scan/nikto-scan.sh`** (CLI-only):
- Iterate `TARGETS[]` array
- `curl -sf` reachability check
- `nikto -h $target -Format csv` output CSV
- Python parse CSV → NDJSON với severity heuristic:
  - HIGH: SQL injection / XSS / RCE / shell / directory listing / auth bypass keywords in desc
  - MEDIUM: OSVDB entry present
  - LOW: info disclosure / server header
  - INFO: default

### 3.3 Filebeat + Logstash routing (CLI-only)

**Filebeat input** (`filebeat.yml`):
```yaml
- type: filestream
  id: vnsoc-vuln
  paths: [/var/log/vnsoc-vuln/trivy-*.ndjson, /var/log/vnsoc-vuln/nikto-*.ndjson]
  parsers: [ndjson: {keys_under_root: true}]
  fields: {source_type: vnsoc-vuln}
```

**Logstash `main.conf`** — filter branch + output:
```ruby
else if [fields][source_type] == "vnsoc-vuln" {
  mutate { add_tag => ["vuln", "vulnerability", "scan"] }
  mutate { add_field => { "[event][category]" => "vulnerability" } }
}
# ... output branch:
else if [@metadata][beat] == "filebeat" and [fields][source_type] == "vnsoc-vuln" {
  elasticsearch { ... index => "vuln-scan-%{+YYYY.MM.dd}" }
}
```

### 3.4 systemd timers (CLI-only)

```
vnsoc-trivy.service  # oneshot ExecStart=/opt/vnsoc-vuln/trivy-scan.sh
vnsoc-trivy.timer    # OnCalendar=*-*-* 02:30:00, Persistent=true
vnsoc-nikto.service
vnsoc-nikto.timer    # OnCalendar=Sun *-*-* 03:00:00
```

Deploy:
```bash
sudo cp vuln-scan/vnsoc-*.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vnsoc-trivy.timer vnsoc-nikto.timer
sudo systemctl list-timers vnsoc-*
```

### 3.5 R18 Kibana rule

**GUI (ưu tiên):**
1. Kibana → **Security → Rules → Create → Custom query**.
2. Source data view: `vuln-scan-*`.
3. Query: `vuln.severity : ("CRITICAL" OR "HIGH") AND event.module : ("trivy" OR "nikto")`.
4. Severity Critical, risk 90.
5. Schedule every 30m, look-back 2h.
6. MITRE T1190 (Exploit Public-Facing App) + T1195 (Supply Chain Compromise).

**CLI:** POST tới `/api/detection_engine/rules` — xem `detection-rules/R18.ndjson`.

---

## 4. Smoke-test results

**Trivy first run:**
```
[2026-07-01T17:34:01] Scanning image: n8nio/n8n:1.74.1
[2026-07-01T17:34:xx] Scanning image: cowrie/cowrie:latest
[2026-07-01T17:34:xx] Scanning fs: /opt/vnsoc-soar
[2026-07-01T17:34:xx] Scanning fs: /etc/logstash
...
[2026-07-01T17:36:37] Trivy scan complete — 768 findings
```

**ES aggregation by severity:**
```
CRITICAL: 89
HIGH:     679
```

**Top vuln targets:**
```
243  n8nio/n8n:1.74.1
166  netdata/netdata:latest
 69  traefik:v3.0
 61  traefik:v2.11
 49  dangnam141002/z-ancestor:latest
```

**Sample CVE finding:**
```json
{
  "@timestamp": "2026-07-01T17:34:01.000Z",
  "vuln": {
    "scanner": "trivy",
    "target": "api-ml-url-api:latest",
    "target_type": "image",
    "cve": "CVE-2026-54369",
    "severity": "HIGH",
    "package": "libacl1",
    "installed_version": "2.3.1-3",
    "fixed_version": "2.3.2-1",
    "title": "libacl: privilege escalation via ACL manipulation",
    "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-54369"
  },
  "event": {"category": "vulnerability", "module": "trivy", "action": "vuln_found"}
}
```

**R18 rule fired trong Kibana Detection Engine** — auto-forward qua alert-forwarder bridge → n8n → TheHive case cho triage.

---

## 5. Lessons learned (Pha 15)

| # | Lesson | Detail |
|---|---|---|
| 1 | Trivy Docker image scan bao gồm base OS + app dependencies | 1 scan `n8nio/n8n:1.74.1` trả 243 findings — mixture of Alpine base + npm packages + system libraries. Analyst nên filter theo `fixed_version` != empty để chỉ tập trung fix được. |
| 2 | `--ignore-unfixed=false` mặc định — Trivy show cả CVE chưa có fix | Nếu bật `true`, giảm 30-50% noise nhưng bỏ qua zero-day. Lab để `false` cho coverage. Production: tune theo policy. |
| 3 | `--severity HIGH,CRITICAL` filter tại scan time — nhẹ hơn filter Kibana | Trivy DB có 200k+ CVEs, filter early tiết kiệm parse time + output size. Trade-off: mất lịch sử LOW/MEDIUM cho compliance report. |
| 4 | Nikto CSV output — dùng `-Format csv -output` không stdout | Stdout format text formatted human-readable, khó parse. CSV có schema cố định 7 cột (Host, IP, Port, OSVDB, Method, URI, Description). |
| 5 | Nikto severity heuristic manual | Nikto không assign severity chuẩn CVSS. Script tự classify theo keyword (SQL injection/XSS/RCE = HIGH; info disclosure = LOW). Production dùng plugin `-Plugins` để chỉ chạy specific tests. |
| 6 | Trivy scan exit code non-zero khi có finding — cẩn thận `set -e` | Bash `set -euo pipefail` sẽ terminate script mid-scan. Bỏ `-e` khỏi trivy-scan.sh giống pha14 yara-scan.sh. |
| 7 | Trivy DB size ~150 MB — cache tại `~/.cache/trivy` | Systemd service run as root → cache `/root/.cache/trivy`. First run 5-8 phút download DB. Sau đó dùng cache 24h before refresh. |
| 8 | Big findings volume → dedup fingerprint | 768 findings mỗi lần scan → cùng CVE + package + target = same fingerprint. Chưa apply dedup Filebeat nhưng dễ thêm sau: `fingerprint filter source: [vuln.cve, vuln.package, vuln.target]` → dùng làm ES `_id`. |

---

## 6. Files sản phẩm

| File | Nội dung |
|---|---|
| `vuln-scan/trivy-scan.sh` | Bash script scan Docker + filesystem → NDJSON |
| `vuln-scan/nikto-scan.sh` | Bash script scan web endpoints → NDJSON |
| `vuln-scan/vnsoc-trivy.{service,timer}` | systemd daily 02:30 |
| `vuln-scan/vnsoc-nikto.{service,timer}` | systemd weekly Sunday 03:00 |
| `fim/yara/filebeat-vpsside.yml` | Filebeat input +1 (vnsoc-vuln) |
| `configs/main.conf` | Logstash filter + output branch cho vnsoc-vuln |
| `detection-rules/R18.ndjson` | Exported R18 rule |
| `pha15-results.md` | Doc này |

---

## 7. Trạng thái Pha 15 cuối

| Component | Status |
|---|---|
| Trivy 0.72 CLI cài trên VPS | ✅ |
| Nikto CLI cài trên VPS | ✅ |
| trivy-scan.sh scan Docker + FS | ✅ 768 findings first run |
| nikto-scan.sh scan Kibana + DVWA | ✅ ready (DVWA scan pending SOC-Tools on) |
| Filebeat input filestream `vnsoc-vuln` | ✅ shipping |
| Logstash filter + output routing | ✅ index vuln-scan-* |
| ES index vuln-scan-* + ILM `vnsoc-30d` | ✅ 768 docs indexed |
| Kibana data view + R18 rule | ✅ enabled |
| systemd timers Trivy + Nikto | ✅ enable --now |
| **Total detection rules** | **18** (R1-R18) |
| **MITRE techniques covered** | **19** (+ T1190 already, + T1195 supply chain new) |

---

## 8. Quick stats

| Metric | Value |
|---|---|
| Detection rules total | 18 (R1-R18) |
| Log source indices | 10 (winlogbeat, suricata, dvwa-apache, wazuh-alerts, syslog, docker, yara-scan, cowrie, ueba, vuln-scan) |
| Filebeat inputs on VPS | 4 (yara + cowrie + ueba + vuln-scan) |
| Trivy findings first scan | 768 (89 CRITICAL + 679 HIGH) |
| Top vulnerable Docker images | n8nio/n8n:1.74.1 (243), netdata/netdata (166), traefik v3.0/v2.11 (130) |
| systemd auto-schedule timers | 5 (soar bridge 30s, ioc daily, yara daily, ueba daily, trivy daily, nikto weekly) |
| Time deploy end-to-end | ~1 giờ |
| Lessons learned | 8 new |

---

## 9. CV talking points

**"Vulnerability management thế nào trong lab?"**
> "I run Trivy container image scanning + Nikto web application scanning as scheduled systemd timers on VPS. Trivy daily 02:30 scans all Docker images + filesystem configs (Logstash/Kibana/Elasticsearch), outputs 768 CVE findings first run — 89 CRITICAL + 679 HIGH. Nikto weekly Sunday 03:00 probes Kibana + DVWA. Results ship to Elasticsearch via Filebeat, R18 detection rule fires on HIGH/CRITICAL → auto-forwards to TheHive case for triage via my existing SOAR bridge. This gives me continuous vuln management as part of my detection engineering discipline — not just detecting attacks but tracking my own attack surface."

**"Trivy vs Grype vs Snyk?"**
> "Trivy = single Go binary, no daemon, offline DB, covers 5 domains: OS packages, app dependencies, IaC misconfigs, secrets, SBOM export. Grype limited to CVE only. Snyk paid + phone-home. Trivy đủ cho lab + production SME, DB refresh mỗi 24h auto."

**"Continuous vuln management vs snapshot scan?"**
> "Snapshot = one-time report. Timer-based = daily baseline, delta detection khi vuln mới xuất hiện trong upstream image (Docker rebuild) hoặc new CVE announcement. R18 fire chỉ trên new findings (dedup planned via fingerprint filter). Feedback loop cho DevSecOps team."

---

## 10. Verify via Kibana GUI

### Trivy CVE findings
1. **Discover → vuln-scan-*** → thấy 768 docs first scan.
2. Add column `vuln.severity`, `vuln.cve`, `vuln.package`, `vuln.target`, `vuln.installed_version`, `vuln.fixed_version`.
3. Filter `vuln.severity : "CRITICAL"` → 89 critical findings.
4. Filter `vuln.scanner : "trivy" AND vuln.target : "n8nio/n8n:1.74.1"` → top vulnerable image (243 findings).
5. Sort desc theo `@timestamp` → xem findings mới nhất.

### Aggregate view — top vulnerable targets
1. **Discover → vuln-scan-*** → nhấn field `vuln.target.keyword` trong left panel → **Visualize** → auto-generate bar chart top 10 target.
2. Alternative: Kibana → **Analytics → Visualize Library → Create → Lens** → drag `vuln.target.keyword` (top values) + count metric.

### R18 alerts triage workflow
1. **Security → Alerts** → filter `kibana.alert.rule.name : "*R18*"` → thấy R18 alerts fire.
2. Click alert → panel expand → view `vuln.cve` + `vuln.primary_url` link tới NVD detail.
3. Alert forward via SOAR bridge → **TheHive** case auto-created cho triage.

### Nikto web scan (khi SOC-Tools online + weekly Sun 03:00 fire)
1. **Discover → vuln-scan-*** → filter `vuln.scanner : "nikto"`.
2. Add column `vuln.uri`, `vuln.method`, `vuln.description`, `vuln.severity`.
3. Filter `vuln.severity : "HIGH"` → SQL injection / XSS / RCE findings.

### systemd timer status check
```
Stack Management → Kibana → không có UI cho systemd.
Alternative: cài Netdata trên VPS (đã có) → localhost:19999 → Systemd Services chart.
```

---

*Pha 15 hoàn tất. Vulnerability management layer stack. Lab bây giờ có full "detect attack + know attack surface" story.*
