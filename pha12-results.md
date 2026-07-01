# Pha 12 — SIEM Depth v2 (CV + ECS aliases + Log Diversification)

> Consolidation update — refresh CV section, add ECS field aliases (non-breaking),
> attempt Lens API build (skipped — schema strict, GUI-only), add multi-source
> Logstash input (syslog + docker JSON) cho log source diversification.

**Ngày thực hiện:** 2026-06-27
**Thời gian:** ~1 giờ
**Hardware change:** None; +2 Logstash input ports (5140, 5145) + UFW rules

---

## 1. Tóm tắt

3/4 items từ CV depth roadmap deployed:

- **#1 CV-section.md update** — added Pha 11 skills (EQL, Sigma, GeoIP+IOC pipeline, Maps+Canvas, ECS aliases) và 4 talking points mới cho SOC interview.
- **#5 ECS field aliases** — non-breaking additive mapping cho `winlogbeat-*`. Analyst có thể query `process.executable`, `user.name`, `file.path`, `registry.key`, `dns.question.name` (ECS standard) trong khi rules cũ dùng `winlog.event_data.*` vẫn work.
- **#4 Lens visualizations** — SKIPPED build via API (Lens saved-object schema strict, phức tạp). Alternative: legacy `visualization` type (4 viz đã build ở Pha 10) hoạt động tương đương. Lens tạo tay qua GUI khuyến khích trong ELK-GUIDE §5.1.
- **#2 Log source diversification** — Logstash input mở thêm:
  - `syslog 5140/tcp+udp` — nhận rsyslog forwarding từ Linux endpoint hoặc network device
  - `tcp 5145` codec `json_lines` — nhận Docker JSON container logs
  - Index tách: `syslog-YYYY.MM.dd` + `docker-YYYY.MM.dd`
  - ILM policy `vnsoc-30d` apply auto qua index template pattern

---

## 2. #5 — ECS Field Aliases (non-breaking)

Aliases là mapping-level pointer trong ES — query-only, không ảnh hưởng document `_source`. Analyst dùng ECS name mà không cần rewrite raw field.

**Aliases đã tạo cho `winlogbeat-*`:**

| ECS field | Alias to (raw) | Sysmon event dùng |
|---|---|---|
| `process.executable` | `winlog.event_data.Image` | Mọi event có process |
| `process.command_line` | `winlog.event_data.CommandLine` | Event 1 |
| `process.pid` | `winlog.event_data.ProcessId` | Mọi event |
| `process.parent.executable` | `winlog.event_data.ParentImage` | Event 1 |
| `process.parent.command_line` | `winlog.event_data.ParentCommandLine` | Event 1 |
| `process.parent.pid` | `winlog.event_data.ParentProcessId` | Event 1 |
| `user.name` | `winlog.event_data.User` | Mọi event |
| `file.path` | `winlog.event_data.TargetFilename` | Event 11 |
| `registry.key` | `winlog.event_data.TargetObject` | Event 12/13/14 |
| `registry.value` | `winlog.event_data.Details` | Event 13/14 |
| `dns.question.name` | `winlog.event_data.QueryName` | Event 22 |

**Test:**
```bash
curl -sk -u "elastic:<PWD>" -X POST "https://localhost:9200/winlogbeat-*/_search?size=1" \
  -H "Content-Type: application/json" \
  -d '{"query":{"exists":{"field":"process.executable"}}}'
# → Trả 10000 docs; alias resolve về winlog.event_data.Image
```

**GUI:** Discover → chọn `winlogbeat-*` → search `process.executable : *powershell*` — work y hệt raw field.

⚠️ **Lesson 1 (Pha 12):** ES alias yêu cầu target field TỒN TẠI trong mapping template. `file.path` alias → `winlog.event_data.TargetFilename` FAIL trong component template vì template chưa có TargetFilename declaration. Fix: apply aliases per-index qua `PUT /<idx>/_mapping` sau khi index đã có doc chứa field đó. Component template chỉ chứa aliases guaranteed present (nhưng test cho thấy tất cả cũng fail → tách hẳn ra `elk-configs/ecs-field-aliases.json` cho per-index PUT).

**File:** `elk-configs/ecs-field-aliases.json`
**Deploy cmd:**
```bash
for idx in $(curl -sk -u "elastic:<PWD>" "https://localhost:9200/_cat/indices/winlogbeat-*?h=index"); do
  curl -sk -u "elastic:<PWD>" -X PUT "https://localhost:9200/$idx/_mapping" \
    -H "Content-Type: application/json" -d @elk-configs/ecs-field-aliases.json
done
```

---

## 3. #4 — Lens visualization deferred

Kibana Lens saved-object schema strict — refuses `references[]` at attributes level. Build via API fails với `mapping set to strict, dynamic introduction of [references] within [lens] is not allowed`.

**Workaround (documented in ELK-GUIDE §5.1):** Build Lens tay qua Kibana GUI (drag-and-drop field vào drop zones). Sau đó export saved-object NDJSON via Stack Management → Saved Objects → Export.

Lab hiện đang có 4 legacy `visualization` type viz + 3 dashboards + Maps + Canvas — đủ CV screenshot demand. Lens rebuild là polish item khi bạn muốn.

---

## 4. #2 — Log source diversification

### 4.1 New Logstash inputs

> **CLI-only.** Logstash pipeline config qua file `/etc/logstash/conf.d/*.conf` — không có GUI edit. Kibana Stack Management → Logstash Pipelines UI (centralized management) tồn tại nhưng cần Elastic Gold license và setup xpack — bỏ qua trong lab Basic.

**File `configs/main.conf` input block:**
```ruby
input {
  beats { port => 5044 }
  syslog {
    port => 5140
    codec => "plain"
    type => "syslog"
  }
  tcp {
    port => 5145
    codec => "json_lines"
    type => "docker"
  }
}
```

**Filter branch mới:**
```ruby
if [type] == "syslog" {
  mutate { add_tag => ["syslog"] }
  mutate { add_field => { "[event][category]" => "host" } }
  mutate { add_field => { "[event][module]" => "syslog" } }
}
if [type] == "docker" {
  mutate { add_tag => ["docker", "container"] }
  mutate { add_field => { "[event][category]" => "container" } }
  mutate { add_field => { "[event][module]" => "docker" } }
}
```

**Output branch mới:**
- `syslog-YYYY.MM.dd` cho syslog messages
- `docker-YYYY.MM.dd` cho JSON container logs

**UFW rules:**
```bash
sudo ufw allow 5140/tcp
sudo ufw allow 5140/udp
sudo ufw allow 5145/tcp
```

### 4.2 Rsyslog client setup (Linux endpoint side)

> **CLI-only (Linux host config).** Rsyslog config file-based. Không có GUI. Windows tương đương: cài NXLog hoặc Winlogbeat (đã cover Pha 2).

**Trên bất kỳ Linux host cần ship syslog:**
```bash
# Add remote destination vào rsyslog config
sudo tee /etc/rsyslog.d/50-vnsoc-remote.conf <<EOF
# Forward all local syslog to VN-SOC Logstash
*.* @@43.228.215.234:5140
EOF
sudo systemctl restart rsyslog

# Test:
logger "VN-SOC syslog test event"
# Wait ~5s
curl -sk -u "elastic:<PWD>" "https://localhost:9200/syslog-*/_search?size=1" \
  -H "Content-Type: application/json" \
  -d '{"query":{"match":{"message":"VN-SOC syslog test"}}}'
```

### 4.3 Docker container JSON logs (SOC-Tools side)

> **CLI-only.** Docker log driver + Filebeat config file-based. Portainer GUI có view container logs realtime nhưng không setup shipper. Kubernetes có sidecar log shipper qua Helm chart — ngoài scope lab.

**Filebeat autodiscover mode config trên bất kỳ Docker host:**
```yaml
# /etc/filebeat/filebeat.yml — nếu dùng Filebeat
filebeat.autodiscover:
  providers:
    - type: docker
      templates:
        - condition: {}
          config:
            - type: container
              paths:
                - /var/lib/docker/containers/${data.docker.container.id}/*.log

output.logstash:
  hosts: ["43.228.215.234:5044"]
```

**Direct Docker log driver (alternative):**
```bash
# Set docker daemon default log driver
sudo tee /etc/docker/daemon.json <<EOF
{
  "log-driver": "syslog",
  "log-opts": {
    "syslog-address": "tcp://43.228.215.234:5140",
    "tag": "{{.Name}}"
  }
}
EOF
sudo systemctl restart docker
```

Hoặc per-container:
```bash
docker run --log-driver=syslog --log-opt syslog-address=tcp://43.228.215.234:5140 nginx
```

---

## 5. Lessons learned (Pha 12)

| # | Lesson | Detail |
|---|---|---|
| 1 | ES field alias target must EXIST in mapping | Component template alias fail nếu target `winlog.event_data.TargetFilename` chưa có trong mapping của index sắp create. Fix: apply aliases per-index sau khi index đã có doc chứa field đó, OR chỉ đưa aliases guaranteed vào template. |
| 2 | Lens saved-object schema strict | API POST fail với `mapping set to strict, dynamic introduction of [references] within [lens] is not allowed`. Lens dụng cụ analyst-only (GUI), không production API-friendly như legacy visualization type. |
| 3 | Syslog input codec plain hay grok? | `codec => plain` để nguyên message field. Muốn parse phải add filter grok theo RFC 3164/5424. Lab chỉ tag basic để demo. Production thêm grok per-service (sshd, sudo, kernel). |
| 4 | JSON codec `json_lines` khác `json` | `json_lines` cho stream mỗi dòng 1 JSON object (Docker log style). `json` cho payload single JSON entire connection. Docker cần `json_lines`. |
| 5 | `syslog` input port 514 privileged | Port <1024 requires root. Logstash chạy user `logstash` không được bind. Dùng port 5140 (unprivileged) + rsyslog client dùng `@@remotehost:5140` (TCP). |

---

## 6. Trạng thái Pha 12 cuối

| Item | Status |
|---|---|
| CV-section.md updated Pha 11 skills | ✅ +4 talking points |
| ECS field aliases (10 aliases) | ✅ applied to 3 winlogbeat indices |
| Lens API build | ❌ SKIPPED — strict schema, GUI-only |
| Logstash syslog input :5140 | ✅ TCP+UDP UFW opened |
| Logstash docker JSON input :5145 | ✅ TCP UFW opened |
| Index patterns `syslog-*` + `docker-*` | ✅ output branch configured |
| Rsyslog client setup docs | ✅ pha12-results.md §4.2 |
| Docker log driver docs | ✅ §4.3 |

---

## 7. Quick stats

| Metric | Value |
|---|---|
| Detection rules | 13 (unchanged) |
| ECS aliases exposed | 10 (`process.*` + `user.*` + `file.*` + `registry.*` + `dns.*`) |
| Logstash inputs | 3 (beats + syslog + docker) |
| Output indices patterns | 5 (winlogbeat + suricata + dvwa-apache + syslog + docker) |
| Total ports Logstash listens | 3 (5044 beats, 5140 syslog TCP+UDP, 5145 docker JSON) |
| CV talking points | 6 (+4 mới) |
| Time end-to-end | ~1 giờ |
| Lessons learned | 5 new |

---

*Pha 12 hoàn tất. Multi-source log ingestion ready cho production expansion. Analyst có thể query ECS name song song raw name.*
