# Pha 11 — SIEM Deep Skills (Detection + Enrichment + Visualization)

> Depth expansion for CV: EQL sequence detection, Sigma rule authoring (portable
> cross-SIEM), 3 new rule types, log enrichment pipeline (GeoIP + UA + IOC),
> world-map + Canvas exec dashboard. Cover 4/6 typical SOC interview questions.

**Ngày thực hiện:** 2026-06-27
**Thời gian:** ~3 giờ
**Hardware change:** No new VM; +2 systemd timer + 1 IOC feed script

---

## 1. Tóm tắt

Pha 11 gộp 3 gói skill:

**A. Detection Language Mastery:**
- R10 EQL sequence rule (multi-stage attack: process → network → LSASS trong 10min)
- R11 Threshold + R12 New Terms + R13 Indicator Match — cover 4/5 Kibana rule types
- Sigma YAML rule authoring + `sigma-cli` converter → portable qua Elastic/Splunk/QRadar/Sentinel

**B. Log Enrichment Pipeline:**
- Logstash geoip filter — src.ip → country/city/ASN/lat-lon
- useragent parser — UA string → os.name/browser/device
- URLhaus IOC feed — 5000 malicious URL paths, refresh daily systemd timer
- Fingerprint filter — SHA256 hash cho dedup

**C. Visualization:**
- Kibana Maps — world-map heatmap attack sources
- Canvas exec dashboard — 1-page presentation-quality workpad

---

## 2. Files sản phẩm

| File | Nội dung |
|---|---|
| `configs/main.conf` | Logstash pipeline updated: geoip + useragent + fingerprint + IOC translate filters |
| `configs/ioc-feed-updater.sh` | Bash cron pull URLhaus CSV → Logstash dictionary YAML |
| `configs/vnsoc-ioc-update.service` + `.timer` | systemd daily 03:00 refresh |
| `detection-rules/sigma/sigma-r1-powershell-encoded.yml` | Sigma YAML for R1 |
| `detection-rules/sigma/sigma-r7-suspicious-ua.yml` | Sigma YAML for R7 |
| `detection-rules/sigma/converted/r1-lucene.txt` + `r1-eql.txt` + `r7-lucene.txt` + `r7-esql.txt` | sigmac converted outputs |
| `pha11-results.md` | doc này |

Kibana Detection Engine rules (deployed via API):
- R10 EQL sequence
- R11 Threshold — Web Login Brute Force
- R12 New Terms — First-Seen Process Image
- R13 Query — URLhaus IOC Match

Saved objects (in `elk-configs/saved-objects/vnsoc-all.ndjson`):
- Map `vnsoc-worldmap` — Suricata alert source.geo.location plotted
- Canvas workpad `vnsoc-exec` — 3 big metrics + title/footer

---

## 3. Detection Language Mastery — chi tiết

### 3.1 R10 — EQL Sequence Rule

**GUI (ưu tiên):**
1. Kibana → **Security → Rules → Detection rules → Create new rule**.
2. Rule type: **Event correlation** (EQL).
3. Source: Data View → `winlogbeat-*`.
4. EQL query paste dưới đây.
5. About: name `[VN-SOC R10] Multi-Stage Attack — Process + Network + LSASS Sequence (EQL)`, severity **Critical**, risk 90.
6. MITRE: T1003.001 (Credential Access) + T1059 (Execution).
7. Schedule: every 5m, look-back 15m.
8. Save & enable.

**CLI (deployed via Kibana Detection Engine REST API — reproducibility):**
```bash
curl -sk -u "elastic:<PWD>" -X POST "http://localhost:5601/api/detection_engine/rules" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" -d @r10-payload.json
```

**Query (EQL syntax):**
```
sequence by host.name with maxspan=10m
  [process where event.code == "1" and winlog.event_data.Image :
    ("*\\powershell.exe", "*\\cmd.exe", "*\\wscript.exe",
     "*\\cscript.exe", "*\\mshta.exe", "*\\rundll32.exe", "*\\regsvr32.exe")]
  [network where event.code == "3" and winlog.event_data.DestinationPort :
    ("80", "443", "8080", "8443")]
  [any where event.code == "10" and winlog.event_data.TargetImage : "*lsass.exe"]
```

**Semantic:** Trong 10 phút trên CÙNG host, nếu có 3 event xảy ra theo thứ tự:
1. Process creation từ shell tool (powershell/cmd/wscript/mshta/rundll32/regsvr32)
2. Network connection outbound tới port 80/443
3. LSASS memory access (Event 10)

→ Fire alert **CRITICAL severity 90**, MITRE T1003.001 (Credential Access) + T1059 (Execution).

**Lý do EQL vs query rule đơn:** attacker thực khi làm credential theft chain (Cobalt Strike, Mimikatz beacon, etc.) sẽ có 3 event này tuần tự. Query rule đơn lẻ chỉ bắt 1 event → false negative cao. EQL sequence gộp lại → **behavioral detection**.

### 3.2 R11 — Threshold Rule (Web Brute Force)

**GUI:** Kibana → Security → Rules → Create → **Threshold** rule type → source `dvwa-apache-*` → query dưới → Threshold field `source.address`, value 20 → schedule 1m/5m.

**CLI:** POST tới `/api/detection_engine/rules` với `type: threshold` + `threshold: {field: [source.address], value: 20}`.

```
Query: url.original : "/login.php" and http.request.method : "POST"
Threshold: source.address >= 20 requests / 5 min
```

Khác R4 (Windows brute force qua Event 4625) — R11 nhìn HTTP layer thay vì Windows Security Event.

### 3.3 R12 — New Terms Rule (Baseline Drift)

**GUI:** Create rule → **New terms** → source `winlogbeat-*` → filter query → "Fields" pick `winlog.event_data.Image.keyword` → history window 14d.

**CLI:** POST rule với `type: new_terms` + `new_terms_fields: [...]` + `history_window_start: "now-14d"`.

```
Query: event.code : "1"
New terms field: winlog.event_data.Image.keyword
History window: 14 days
```

Alert khi 1 process Image chạy lần đầu trong 14 ngày. Catch:
- New malware executable dropped
- Persistence artifact
- Legitimate new admin tool cần whitelist

### 3.4 R13 — Indicator Match / Threat Intel

**GUI:** Kibana → Security → Rules → Create → **Custom query** rule → source `dvwa-apache-*` → paste query dưới → severity Critical.

**CLI:** POST rule với `type: query`.

Không dùng built-in `threat_match` rule type (require indicator index). Thay bằng plain `query` rule check tag `ioc_match` mà Logstash translate filter đã add (§4.3).

**Query:** `threat.indicator.provider : "urlhaus_recent" and tags : "ioc_match"`

Simple, low-latency, no ES join. Trade-off: chỉ match paths trong dictionary, không match hash/domain (nhưng URLhaus feed dùng URL nên OK).

### 3.5 Sigma workflow

Sigma là ngôn ngữ detection **portable cross-SIEM**. Viết YAML 1 lần → convert sang KQL / Lucene / EQL / ES|QL / Splunk SPL / Sentinel KQL / etc.

> **CLI-only workflow.** Sigma community không có official GUI. Alternatives tương đương:
> - Online: `https://uncoder.io/` (SOC Prime — free) — paste Sigma YAML → chọn backend → generate KQL/Lucene/SPL.
> - VS Code extension: `Sigma Language Support` (syntax highlighting + validate).

**Cài `sigma-cli`:**
```bash
pip3 install --user sigma-cli pysigma-backend-elasticsearch
```

**Ví dụ Sigma YAML (R7 web attack UA):**
```yaml
title: Web Attack Tool User-Agent Detection
id: 4e1059ed-5f3f-4357-add2-80e0d7470c19
status: stable
description: Detects HTTP requests from known web attack tool User-Agents
tags:
  - attack.reconnaissance
  - attack.t1595.002
logsource:
  product: apache
  service: access
detection:
  selection:
    user_agent.original|contains:
      - 'sqlmap'
      - 'nikto'
      - 'Nmap'
      - 'Nessus'
  condition: selection
level: high
```

**Convert:**
```bash
export PATH=$PATH:~/.local/bin
sigma convert -t lucene --without-pipeline sigma-r7-suspicious-ua.yml
# → user_agent.original:(*sqlmap* OR *nikto* OR *Nmap* OR *Nessus* ...)

sigma convert -t esql --without-pipeline sigma-r7-suspicious-ua.yml
# → from * metadata _id, _index, _version | where user_agent.original like "*sqlmap*" ...

sigma convert -t eql -p ecs_windows sigma-r1-powershell-encoded.yml
# → any where ((process.executable like~ ("*\\powershell.exe", "*\\pwsh.exe", ...
```

**CV story:** *"I write detection rules in Sigma (portable) — sigmac converts them to KQL for Elastic, SPL for Splunk, KQL for Sentinel. Same source, no vendor lock-in."*

---

## 4. Log Enrichment Pipeline — chi tiết

### 4.1 GeoIP filter

> **CLI-only.** Logstash config file-based, không có GUI Kibana cho pipeline edit. Kibana Stack Management → Logstash Pipelines UI TỒN TẠI nhưng ít dùng production. Đại đa số SOC dùng file `/etc/logstash/conf.d/*.conf` + git version control + CI/CD deploy.

`main.conf` thêm sau grok:
```ruby
if [src_ip] and [src_ip] !~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.)/ {
  geoip {
    source => "src_ip"
    target => "[source][geo]"
    fields => ["country_name","country_code2","city_name","region_name","location","timezone"]
  }
  geoip {
    source => "src_ip"
    target => "[source][as]"
    default_database_type => "ASN"
    fields => ["AUTONOMOUS_SYSTEM_NUMBER","AUTONOMOUS_SYSTEM_ORGANIZATION"]
  }
}
```

⚠️ **Lesson 1 (Pha 11):** GeoIP ASN field name PHẢI uppercase (`AUTONOMOUS_SYSTEM_NUMBER`, không phải `asn`) — MaxMind DB library requirement. Sai → Logstash pipeline fail startup với `illegal field value asn`.

⚠️ **Lesson 2:** Regex `!~` exclude RFC1918 private IPs. Không exclude → geoip return null gracefully nhưng waste CPU cho mọi doc.

### 4.2 UserAgent parser

```ruby
if [user_agent][original] {
  useragent {
    source => "[user_agent][original]"
    target => "[user_agent]"
  }
}
```

Sau parse, có `user_agent.name` (browser), `user_agent.os.name`, `user_agent.device.name`. Discover column dễ đọc.

### 4.3 URLhaus IOC feed

**Script `configs/ioc-feed-updater.sh`:**
1. `curl https://urlhaus.abuse.ch/downloads/csv_recent/` → CSV plain (30-day recent, ~30k URLs).
2. Extract column 3 (url) từ CSV format `"id","dateadded","url",...`.
3. Python parse URL → extract path (`/malware.exe`).
4. Output YAML dict cho Logstash translate: `'/malware.exe': 'urlhaus_recent'`.
5. Cap 5000 entries (perf).

**systemd timer:** OnCalendar=daily + RandomizedDelaySec=30m.

**Logstash filter:**
```ruby
if [url][original] {
  translate {
    source => "[url][original]"
    target => "[threat][indicator][provider]"
    dictionary_path => "/etc/logstash/ioc/urlhaus-paths.yml"
    refresh_interval => 3600
    fallback => ""
  }
  if [threat][indicator][provider] and [threat][indicator][provider] != "" {
    mutate {
      add_tag => ["ioc_match", "urlhaus"]
      add_field => { "[threat][indicator][type]" => "url" }
    }
  } else {
    mutate { remove_field => ["[threat][indicator][provider]"] }
  }
}
```

**Lesson 3 (Pha 11):** URLhaus KHÔNG zip nữa (docs cũ nói zip). Download trả plain CSV — sửa script bỏ unzip.

**Lesson 4:** Dictionary size trade-off — 30k paths → Logstash memory bloat + slow reload. Cap 5000 = balance.

### 4.4 Fingerprint dedup

```ruby
if [source][address] and [url][original] {
  fingerprint {
    source => ["[source][address]", "[url][original]", "[http][request][method]"]
    target => "[event][hash]"
    method => "SHA256"
    concatenate_sources => true
  }
}
```

`event.hash` SHA256 của `src+url+method`. Same triple → same hash → có thể dùng làm ES `_id` để dedup (advanced pattern, chưa apply trong lab).

---

## 5. Lessons learned (Pha 11)

| # | Lesson | Detail |
|---|---|---|
| 1 | GeoIP ASN field PHẢI uppercase | `asn` → `AUTONOMOUS_SYSTEM_NUMBER`. Docs ambiguous, chỉ ra khi Logstash startup crash. |
| 2 | RFC1918 exclude regex | Lab đa số IP private, không exclude → waste enrichment CPU. |
| 3 | URLhaus CSV plain, không zip | Script cũ dùng unzip → fail. Curl trả plain text. |
| 4 | IOC dictionary size cap 5000 | 30k paths reload chậm + memory bloat. |
| 5 | Sigma rule cần UUID | `id` field PHẢI valid UUID (regex). sigma-cli reject non-UUID. |
| 6 | Sigma `--without-pipeline` cho custom logsource | Nếu logsource là niche (apache, dvwa) không có pipeline built-in → thêm flag. |
| 7 | EQL sequence maxspan critical | 10m too short = miss slow-attack; too long = FP. Tune based on attacker TTPs. |
| 8 | New Terms history_window_start required | Không set = rule không fire (không có baseline). Mặc định 14 ngày OK cho endpoint fleet stability. |
| 9 | Threshold rule field.keyword | `source.address` là `text` — dùng `source.address.keyword` cho aggregation chính xác. Kibana handle auto nhưng edge cases fail. |
| 10 | Canvas expression escaping | Sub-quotes `\\"` inside `essql query="..."` — nested escape trong JSON payload. Debug qua `docker logs`. |

---

## 6. Trạng thái cuối Pha 11

| Item | Status |
|---|---|
| Logstash geoip filter | ✅ + Rejected startup 1 lần (uppercase fix) |
| useragent parser | ✅ |
| Fingerprint filter | ✅ |
| URLhaus IOC feed + systemd timer daily | ✅ 5000 paths loaded |
| Sigma workflow + sigma-cli install | ✅ 2 YAML + 4 converted outputs |
| R10 EQL sequence rule | ✅ enabled, MITRE T1003.001+T1059 |
| R11 Threshold rule | ✅ enabled, MITRE T1110 |
| R12 New Terms rule | ✅ enabled, MITRE T1204 |
| R13 Query indicator match | ✅ enabled, MITRE T1189 |
| Total Kibana rules | ✅ **13** (up from 9) |
| Kibana Maps `vnsoc-worldmap` | ✅ Suricata source.geo layer |
| Canvas workpad `vnsoc-exec` | ✅ 3 big-metric + title/footer |

---

## 7. Quick stats

| Metric | Value |
|---|---|
| Detection rules total | 13 (R1-R13) |
| Rule types coverage | 4/5 (query, threshold, eql, new_terms) — chỉ thiếu `threat_match` (paid) |
| MITRE techniques covered | **11** unique (T1003.001, T1027, T1059/.001, T1071.001, T1083, T1110, T1189, T1190, T1204, T1547.001, T1595/.002) |
| Log enrichment fields added | ~15 (source.geo.* + source.as.* + user_agent.* + event.hash + threat.indicator.*) |
| IOC feed size | 5000 URLhaus paths, refresh daily |
| Sigma rules authored | 2 YAML + 4 backends converted |
| Kibana saved objects | +2 (Map + Canvas) |
| Time end-to-end | ~3 giờ + ~30 phút debug |
| Lessons learned | 10 new |

---

## 8. Verify via Kibana GUI

### R10 EQL sequence rule
1. **Security → Rules → Detection rules** → tìm `[VN-SOC R10]` → click → tab **Rule execution results** → xem last run status (Success/Failed) + alerts count per run.
2. **Security → Alerts** → filter `kibana.alert.rule.uuid : <R10-uuid>` → nếu Win10 endpoint có chain process→network→LSASS trong 10min thì thấy alert.

### R11-R13 rules
1. **Security → Rules** → filter tags `VN-SOC-Lab` → thấy 13 rules R1-R13.
2. Click R11 → tab About → xem MITRE T1110 + Kibana rule type Threshold.
3. **Security → Alerts** → filter theo `kibana.alert.rule.name : "*R13*"` → thấy indicator match alerts nếu URL match URLhaus feed.

### GeoIP enrichment verify
1. **Discover → suricata-*** → filter `source.geo.location : *` → thấy docs với `source.geo.country_name`, `source.as.organization_name`.
2. **Analytics → Maps → VN-SOC: World Map — Attack Sources GeoIP** → world map render 7+ pins (synthetic external IPs từ smoke-test).
3. Add column `source.geo.city_name`, `source.geo.country_code2`, `source.as.AUTONOMOUS_SYSTEM_ORGANIZATION`.

### UserAgent parser verify
1. **Discover → dvwa-apache-*** → add column `user_agent.name`, `user_agent.os.name`, `user_agent.device.name`.
2. Filter `user_agent.name : "curl"` → thấy attack tool requests.

### URLhaus IOC feed verify
1. **Discover → dvwa-apache-*** → filter `tags : "ioc_match"` → thấy events matched malicious URL paths.
2. Field `threat.indicator.provider : "urlhaus_recent"` xuất hiện trong tab Table doc detail.
3. **Analytics → Canvas → VN-SOC Executive Dashboard** → embed 3 metrics count.

---

*Pha 11 hoàn tất. SIEM deep skills stack. Sẵn sàng CV interview cho SOC Analyst / Detection Engineer roles.*
