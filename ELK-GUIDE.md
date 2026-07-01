# ELK — Analyst Field / Discover / Dashboard Guide

> Hướng dẫn xem log Kibana đúng cách cho analyst VN-SOC. Trả lời 3 câu hỏi:
> 1. Field trong Data View đến từ đâu?
> 2. Xem log gọn ghẽ trong Discover thế nào (không bị lóa mắt bởi 500 field)?
> 3. Custom dashboard chuyên nghiệp thế nào + production ELK ops (ILM, runtime fields)?

**Ngày cập nhật:** 2026-06-27
**Áp dụng cho:** Elastic 8.19.17 + Kibana 8.19.17 + Logstash 8.19.17

---

## 1. Field đến từ đâu — chain 5 layer

```
┌────────────────────────────────────────────────────────────────┐
│ 5. Kibana Data View                                            │
│    - Runtime fields (analyst tự add)                           │
│    - Field formatters (bytes, url, IP display)                 │
│    - Field popularity (count) → boost trong Discover           │
├────────────────────────────────────────────────────────────────┤
│ 4. Elasticsearch                                               │
│    - `.keyword` sub-field auto cho text                        │
│    - `_id`, `_index`, `_source` meta                           │
├────────────────────────────────────────────────────────────────┤
│ 3. Logstash pipeline `main.conf`                               │
│    - translate plugin: `event.action` từ event_id              │
│    - mutate/add_tag: `tags`, `event.category`                  │
│    - grok Apache log → `source.address`, `url.original`        │
│    - http filter (Pha 8): `ml.label`, `ml.score`               │
├────────────────────────────────────────────────────────────────┤
│ 2. Shipper — Winlogbeat / Filebeat                             │
│    - `agent.*`, `ecs.version`, `host.*`                        │
│    - `event.code`, `event.provider`                            │
│    - `@timestamp`, `input.type`                                │
├────────────────────────────────────────────────────────────────┤
│ 1. Sensor — Sysmon driver / Windows Security / Suricata / Apache│
│    - `winlog.event_data.*` (Image, CommandLine, Hashes, ...)   │
│    - Suricata `eve.json` (alert.*, http.*, dns.*)              │
│    - Apache raw log (chưa parse)                               │
└────────────────────────────────────────────────────────────────┘
```

**Điểm quan trọng:**
- Muốn **thêm field custom**: sửa Logstash `main.conf` (layer 3). Xem Pha 8 §3.7 (http filter thêm `ml.*`).
- Muốn **rename field cho readable**: `mutate { rename => [...] }` trong Logstash. Cẩn thận không phá KQL rule.
- Muốn field **compute runtime** (không reindex): dùng runtime field trong Kibana Data View (layer 5).

## 2. Field thực tế dùng — column preset cho từng nguồn

Trong Kibana Discover, chọn **Data View** → click **field name** trong left panel → chuyển thành column. Hoặc **Open saved search** để load preset ngay.

### 2.1 Sysmon Process Creation (event.code: "1")
```
@timestamp | host.name | winlog.event_data.User | winlog.event_data.Image
  | winlog.event_data.CommandLine | winlog.event_data.ParentImage
```

### 2.2 Sysmon Network Connection (event.code: "3")
```
@timestamp | host.name | winlog.event_data.Image | winlog.event_data.DestinationIp
  | winlog.event_data.DestinationPort | winlog.event_data.DestinationHostname
```

### 2.3 Sysmon Registry Set (event.code: "13")
```
@timestamp | host.name | winlog.event_data.Image | winlog.event_data.TargetObject
  | winlog.event_data.Details
```

### 2.4 Windows Security Logons (event.code: "4624"/"4625")
```
@timestamp | host.name | event.action | winlog.event_data.TargetUserName
  | winlog.event_data.LogonType | winlog.event_data.IpAddress | winlog.event_data.WorkstationName
```

### 2.5 Suricata Alerts (event_type: "alert")
```
@timestamp | src_ip | dest_ip | dest_port | alert.signature | alert.category | alert.severity
```

### 2.6 DVWA + ML enrichment (Pha 8)
```
@timestamp | source.address | http.request.method | url.original
  | http.response.status_code | ml.score | attack_score | user_agent.original
```

**Rule of thumb:** Winlogbeat có ~500 field, analyst dùng 15-20. Tỷ lệ 4%.

## 3. Saved Searches — mở Discover với column set sẵn

Repo đã build sẵn **6 saved searches**. Load qua Kibana Discover → **Open** (icon folder top-right):

| Saved Search | Data View | Column preset |
|---|---|---|
| `VN-SOC: Sysmon Process Creation` | winlogbeat-* | §2.1 |
| `VN-SOC: Sysmon Network Connection` | winlogbeat-* | §2.2 |
| `VN-SOC: Sysmon Registry Set` | winlogbeat-* | §2.3 |
| `VN-SOC: Windows Security Logons` | winlogbeat-* | §2.4 |
| `VN-SOC: Suricata Alerts` | suricata-* | §2.5 |
| `VN-SOC: DVWA Web Attack with ML Score` | dvwa-apache-* | §2.6 |

**Reproduce ở Kibana lab mới:**
- **GUI:** Stack Management → Saved Objects → Import → chọn `elk-configs/saved-objects/vnsoc-all.ndjson`
- **CLI:**
```bash
ssh vps 'curl -sk -u "elastic:<PWD>" -X POST \
  "http://localhost:5601/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" -F file=@/tmp/vnsoc-all.ndjson'
```

## 4. Dashboards đã build sẵn (3 dashboards)

### 4.1 VN-SOC Overview
- **Total Alerts (24h)** — metric big number
- **Suricata Alerts by Category** — pie chart
- **Top Source IPs (Suricata)** — bar chart

Filter theo time range → get executive view của attack surface.

### 4.2 VN-SOC Endpoint Activity
- Sysmon Process Creation (saved search embed)
- Sysmon Network Connection
- Sysmon Registry Set
- Windows Security Logons

Drill-down endpoint investigation — click bất kỳ row trong panel → filter cross panels.

### 4.3 VN-SOC Web Attack Surface
- ML Score Distribution — histogram bucket 0.0-1.0
- Suricata Alerts (saved search)
- DVWA Web Attack with ML Score

Web-focused view. Filter `ml.label: malicious` → còn attack thực sự.

## 5. Build custom dashboard tự tay (Kibana 8.x Lens)

### 5.1 Workflow tạo Lens visualization
1. Kibana → **Visualize Library → Create visualization → Lens**.
2. Chọn **Data View** (winlogbeat-* / suricata-* / dvwa-apache-*).
3. Left panel: drag **field** vào **Metric / Horizontal axis / Vertical axis** slot.
4. Chart type dropdown: **Bar vertical stacked / Line / Metric / Pie / Data table / Heat map / Treemap**.
5. **Save** → tên `VN-SOC: <mục đích>` — thêm vào Visualize Library.

### 5.2 Common patterns

**Time series alerts by rule:**
- Data View: `.internal.alerts-security.alerts-default-*`
- X-axis: `@timestamp` (Date histogram)
- Y-axis: Count
- Break down by: `kibana.alert.rule.name.keyword`

**Attacker top IPs:**
- Data View: `suricata-*`
- Chart: Bar horizontal
- X-axis: Count
- Y-axis: `src_ip.keyword` (Top values, size 10, order desc)
- Filter: `event_type: "alert"`

**ML enrichment heatmap:**
- Data View: `dvwa-apache-*`
- Chart: Heat map
- X-axis: `@timestamp` (hour buckets)
- Y-axis: `ml.label.keyword` (Top values)
- Cell: Average `ml.score`

### 5.3 Assemble dashboard
1. Kibana → **Dashboard → Create dashboard**.
2. **Add from library** → chọn multiple viz + saved searches.
3. Drag resize panels. Recommend grid:
   - Metric big number ở top (impact stats)
   - Pie/bar row 2 (breakdown by category)
   - Saved search table row 3 (drill-down rows)
4. **Save** với title `VN-SOC: <domain>` → tag `vn-soc-lab`.

## 6. Runtime field — compute mà không reindex

Runtime field = Painless script tính field mới **tại query time**. KHÔNG ghi vào ES index — mỗi lần query recompute.

**Ví dụ đã build: `attack_score` cho `dvwa-apache-*`:**
```painless
double s = 0.0;
if (doc.containsKey('ml.score') && !doc['ml.score'].empty) {
  s = doc['ml.score'].value * 100.0;
  if (doc.containsKey('ml.label.keyword') && !doc['ml.label.keyword'].empty
      && doc['ml.label.keyword'].value == 'malicious') { s += 20.0; }
  if (doc.containsKey('http.response.status_code') && !doc['http.response.status_code'].empty
      && doc['http.response.status_code'].value >= 400) { s += 10.0; }
}
emit(s);
```

**Kết quả:** SQLi attack ml.score=0.67, label=malicious → attack_score = 67 + 20 = **87.06**.

### GUI (Kibana) tạo runtime field:
1. **Stack Management → Data Views → chọn `dvwa-apache-*`**.
2. Tab **Runtime fields → Add field**.
3. Type: `double` (hoặc keyword/date/long/boolean).
4. Paint script trong text area → **Preview** → **Save**.

### CLI:
```bash
DVW_ID="db37285a-ce04-4af2-8b12-ca6a497ad98f"
curl -sk -u "elastic:<PWD>" -X POST \
  "http://localhost:5601/api/data_views/data_view/$DVW_ID/runtime_field" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d @attack_score-runtime-field.json
```

**Khi nào dùng runtime vs Logstash pipeline field:**
- **Runtime** = ít dùng, ad-hoc analyst experiment, don't want reindex.
- **Logstash pipeline** = production, high query volume — trade-off compute-once-at-index vs compute-at-query.

## 7. ILM (Index Lifecycle Management) — production ops

Lab đã setup policy `vnsoc-30d` với 3 phase:
- **Hot** (0-7d): active writes, rollover if 5GB shard hoặc 7d
- **Warm** (7-30d): shrink to 1 shard, forcemerge, priority=50
- **Delete** (30d+): auto-delete

Index template `vnsoc-lab` (`index_patterns: [winlogbeat-*, suricata-*, dvwa-apache-*]`) auto-apply ILM policy cho index mới.

### Verify ILM working:
```bash
ssh vps 'curl -sk -u "elastic:<PWD>" "https://localhost:9200/_ilm/policy/vnsoc-30d?pretty"'
ssh vps 'curl -sk -u "elastic:<PWD>" "https://localhost:9200/winlogbeat-*,suricata-*,dvwa-apache-*/_ilm/explain?pretty"'
```

**Expected output:**
```json
{
  "indices": {
    "winlogbeat-2026.06.27": {
      "policy": "vnsoc-30d",
      "phase": "hot",
      "age": "3.5h",
      ...
    }
  }
}
```

### Retention tuning
Sửa policy `vnsoc-30d` → thay `delete.min_age` = "90d" nếu muốn giữ 90 ngày:
```bash
curl -sk -u "elastic:<PWD>" -X PUT "https://localhost:9200/_ilm/policy/vnsoc-30d" \
  -H "Content-Type: application/json" -d '{ "policy": {...} }'
```

## 8. Field cleanup — quản lý noise 500 field

### 8.1 Field popularity (đã set)
Data View có field `count` — Kibana Discover sort field theo count desc. Lab đã boost core fields = 20 cho 3 data view. Muốn thêm:

**GUI:** Stack Management → Data Views → chọn data view → tab Fields → click ⚙ next to field → set popularity.

**CLI:**
```bash
curl -sk -u "elastic:<PWD>" -X POST \
  "http://localhost:5601/api/data_views/data_view/<DV_ID>/fields" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{"fields":{"field.name":{"count":20}}}'
```

### 8.2 Hide fields hoàn toàn
Data View → tab Fields → click field → **Format tab** → toggle **Hidden**.

Hoặc mass hide qua API — chỉnh `fieldAttrs`:
```bash
curl -sk -X POST "http://localhost:5601/api/data_views/data_view/<DV_ID>/fields" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -d '{"fields":{"agent.ephemeral_id":{"customLabel":"","count":0}}}'
```

### 8.3 Advanced Settings
Stack Management → **Advanced Settings**:
- `discover:searchFieldsFromSource: true` — load ít field hơn khi search
- `discover:rowHeightOption: 3` — hiển thị 3 dòng per row (đọc CommandLine dài dễ hơn)
- `defaultColumns: ["@timestamp","host.name","event.action"]` — set global column default

## 9. Deploy nhanh vào Kibana khác

Import bundle NDJSON:

**GUI (ưu tiên):**
1. Stack Management → **Saved Objects → Import**.
2. Chọn `elk-configs/saved-objects/vnsoc-all.ndjson` — chứa 3 dashboards + 4 viz + 6 searches + 3 data views.
3. Conflict resolution: **Overwrite existing**.
4. Xong → mở Dashboard menu → thấy 3 dashboard mới prefix "VN-SOC".

**CLI:**
```bash
ssh vps 'curl -sk -u "elastic:<PWD>" -X POST \
  "http://localhost:5601/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" -F file=@vnsoc-all.ndjson'
```

Import ILM policy:
```bash
ssh vps 'curl -sk -u "elastic:<PWD>" -X PUT \
  "https://localhost:9200/_ilm/policy/vnsoc-30d" \
  -H "Content-Type: application/json" -d @elk-configs/ilm-vnsoc-30d.json'
```

Import index template:
```bash
ssh vps 'curl -sk -u "elastic:<PWD>" -X PUT \
  "https://localhost:9200/_index_template/vnsoc-lab" \
  -H "Content-Type: application/json" -d @elk-configs/index-template-vnsoc.json'
```

## 10. Production ELK adds — roadmap tiếp

Đã có: ILM policy + index template + saved objects + runtime field.

Còn có thể thêm (khi cần):

| Add | Use case | Effort |
|---|---|---|
| **Filebeat modules** (auditd/syslog/system) | Ship thêm Linux audit + syslog | 30 phút |
| **Watcher** (Basic license limited) | Time-based alert trigger email/webhook | 1h |
| **Elastic Agent + Fleet** | Replace Winlogbeat với centralized policy | 2h (heavy) |
| **Canvas** | Presentation workspace cho executive report | 1h |
| **Maps** | Geo visualization (src_ip → country flag on world map) | 30 phút |
| **APM** (paid) | Application performance tracing | 2h |
| **ML anomaly detection** (paid Trial) | Auto-baseline user/host behavior | 1h |
| **Cross-cluster search** | Multi-region Elastic federation | complex |

Xem `roadmap.md` nếu muốn ưu tiên item nào.

---

## 11. Cheat sheet — Kibana KQL commonly used

```
# Time
@timestamp >= "now-15m"

# Multi-value
event.code : ("1" or "3" or "22")

# Wildcard (dùng .keyword field)
winlog.event_data.Image.keyword : *\\powershell.exe*

# Range
ml.score >= 0.7

# Boolean
event_type : "alert" and alert.severity : 1

# Exclude
NOT winlog.event_data.Image.keyword : (*\\OneDrive*.exe OR *\\Teams.exe)

# Exists (field có value)
url.original : *

# Nested field access — cả 2 syntax work
event.code : "1"
event : { code : "1" }
```

---

*Guide này = docs cho analyst dùng ELK stack VN-SOC daily. Cập nhật cùng với các Pha mới khi thêm data source / field.*
