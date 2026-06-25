# VN-SOC Lab — Báo cáo Dự án

> **Mô phỏng Security Operations Center quy mô doanh nghiệp Việt Nam**
> *End-to-end SIEM • Detection Engineering • Adversary Emulation • Incident Response*

---

## Thông tin nhanh

| Mục | Giá trị |
|---|---|
| Tên dự án | VN-SOC Lab |
| Tác giả | namth (`gnid31`) |
| Bắt đầu | 2026-06-23 |
| Cập nhật cuối | 2026-06-25 |
| Trạng thái | 🔄 Đang triển khai — Pha 2 |
| Repo | github.com/gnid31/vn-soc-lab (private) |

> ⚠️ **Quy ước viết báo cáo này:** file `report.md` CHỈ ghi lại những phần đã thực thi và verify thành công. Kế hoạch các pha sắp tới nằm trong [`roadmap.md`](roadmap.md). Mỗi commit sửa file này đi kèm 1 dòng trong [`CHANGELOG.md`](CHANGELOG.md).

---

## Mục lục

1. [Tóm tắt điều hành](#1-tóm-tắt-điều-hành)
2. [Bối cảnh & mục tiêu](#2-bối-cảnh--mục-tiêu)
3. [Kiến trúc hệ thống](#3-kiến-trúc-hệ-thống)
4. [Pha 1 — SIEM Backend (hoàn tất)](#4-pha-1--siem-backend-hoàn-tất)
5. [Pha 2 — Endpoint Telemetry (đang làm)](#5-pha-2--endpoint-telemetry-đang-làm)
6. [Sự cố & xử lý đã ghi nhận](#6-sự-cố--xử-lý-đã-ghi-nhận)
7. [Hardening đã áp dụng vs còn thiếu](#7-hardening-đã-áp-dụng-vs-còn-thiếu)
8. [Kỹ năng đã chứng minh tới hiện tại](#8-kỹ-năng-đã-chứng-minh-tới-hiện-tại)
9. [Phụ lục — lệnh tham khảo](#9-phụ-lục--lệnh-tham-khảo)

---

## 1. Tóm tắt điều hành

**Đến thời điểm cập nhật cuối**, dự án đã hoàn tất **Pha 1** (triển khai SIEM backend trên VPS Cloud) và đang ở giữa **Pha 2** (telemetry endpoint Windows 10).

Stack đang chạy:

```
┌──────────────────────────┐    TCP 5044    ┌──────────────────────┐
│  Windows 10 victim       │ ─────────────→ │  Logstash 8.19.17    │
│  Sysmon + Winlogbeat     │                │  pipeline winlogbeat │
│  (Pha 2 — in progress)   │                └─────────┬────────────┘
└──────────────────────────┘                          │ HTTPS 9200
                                                      ▼
                                          ┌────────────────────────┐
                                          │  Elasticsearch 8.19.17 │
                                          │  + Kibana 8.19.17      │
                                          │  (Pha 1 — done)        │
                                          └────────────────────────┘
                                            VPS 43.228.215.234
```

**Truy cập:**

| Endpoint | URL/Port | Trạng thái |
|---|---|---|
| Kibana UI | http://43.228.215.234:5601 | ✅ HTTP 200 từ external |
| Elasticsearch HTTPS | https://localhost:9200 (trên VPS) | ✅ green |
| Logstash Beats input | 43.228.215.234:5044 | ✅ Listening, events_in = 0 |

---

## 2. Bối cảnh & mục tiêu

### 2.1 Bài toán mô phỏng

Một SOC Analyst entry-level trong ngân hàng / fintech Việt Nam thường phải:

1. **Tiếp nhận** event từ nhiều nguồn log (endpoint, firewall, IDS, application).
2. **Xác định** alert nào là true positive đáng điều tra.
3. **Điều tra** theo MITRE ATT&CK kill-chain.
4. **Báo cáo** theo template Incident Report chuẩn.

Lab này dựng phiên bản thu nhỏ của cả 4 bước trên để có deliverable cụ thể cho CV.

### 2.2 Mục tiêu đo lường được

| # | Mục tiêu | Đạt khi |
|---|---|---|
| 1 | SIEM stack on-prem bare-metal | ✅ 3 service active + enable + Kibana truy cập public |
| 2 | Endpoint Windows ship log | 🔄 Sysmon + Winlogbeat đẩy event vào `winlogbeat-*` |
| 3 | Detection rule mapping MITRE | ⏳ Pha 3 |
| 4 | Adversary emulation | ⏳ Pha 4 |
| 5 | Incident Report mẫu | ⏳ Pha 5 |
| 6 | Document trade-off bảo mật | 🔄 đang cập nhật theo từng pha |

### 2.3 Phạm vi & ngoài phạm vi

- **Trong phạm vi:** Detection thuần (defensive), 1 endpoint Windows, 1 SIEM node.
- **Ngoài phạm vi:** SOAR đầy đủ, malware reverse engineering, compliance audit (PCI-DSS, ISO 27001).

---

## 3. Kiến trúc hệ thống

### 3.1 Sơ đồ tổng thể

```
                       ┌──────────────────────────────────────────────┐
                       │             ANALYST WORKSTATION              │
                       │  (Windows host — browser + SSH client)        │
                       └──────────┬──────────────────────┬────────────┘
                                  │ HTTP 5601            │ SSH 22
                                  ↓                      ↓
              ╔═══════════════════════════════════════════════════════╗
              ║          VPS Cloud — 43.228.215.234 (Ubuntu 24.04)   ║
              ║                                                       ║
              ║  ┌──────────────────────────────────────────────┐    ║
              ║  │ Kibana 8.19.17 (0.0.0.0:5601) — Web UI       │    ║
              ║  └────────────────────┬─────────────────────────┘    ║
              ║                       │ HTTPS 9200 (loopback)        ║
              ║                       ↓                              ║
              ║  ┌──────────────────────────────────────────────┐    ║
              ║  │ Elasticsearch 8.19.17                        │    ║
              ║  │ - heap 512 MB                                │    ║
              ║  │ - X-Pack Security ON (TLS self-signed)       │    ║
              ║  │ - index: winlogbeat-YYYY.MM.dd               │    ║
              ║  └──────────────────────────────────────────────┘    ║
              ║                       ↑                              ║
              ║                       │ HTTPS 9200 (loopback)        ║
              ║  ┌──────────────────────────────────────────────┐    ║
              ║  │ Logstash 8.19.17                             │    ║
              ║  │ - Pipeline: configs/winlogbeat.conf          │    ║
              ║  │ - Input:  beats { port => 5044 }             │    ║
              ║  │ - Filter: ECS v8, Sysmon + Security mapping  │    ║
              ║  │ - Output: ES https://localhost:9200          │    ║
              ║  └──────────────────────┬───────────────────────┘    ║
              ║                         ↑                            ║
              ║                         │ TCP 5044 (Beats Lumberjack)║
              ║         UFW: 22, 5044, 5601 (9200 đóng)              ║
              ╚═════════════════════════│════════════════════════════╝
                                        │ Public Internet
                                        ↓
                ╔════════════════════════════════════════════════════╗
                ║   ENDPOINT — Windows 10 (Pha 2, in progress)      ║
                ║   - Sysmon v15 + SwiftOnSecurity config            ║
                ║   - Winlogbeat 8.19 service                        ║
                ║   - Channels: Security/System/App/Sysmon/PS       ║
                ╚════════════════════════════════════════════════════╝
```

### 3.2 Lý do thiết kế tách Logstash khỏi port ES

1. **Tách trách nhiệm:** Logstash là nơi normalize/enrich; Beats chỉ transport.
2. **Bảo mật firewall:** `:9200` đóng kín — kẻ tấn công không có index API public.
3. **Enrich tập trung:** Khi thêm nguồn mới (Wazuh, Suricata), cùng đi qua 1 cửa.
4. **Backpressure:** Persistent queue ở Logstash giữa input/output, ES sập không mất event.

---

## 4. Pha 1 — SIEM Backend (hoàn tất)

**Hoàn tất:** 2026-06-25
**Mục tiêu:** Cài Elasticsearch + Kibana + Logstash 8.x trên VPS, bind Kibana public, enable auto-start, hardening cơ bản.

### 4.1 VPS spec

| | |
|---|---|
| OS | Ubuntu 24.04.2 LTS |
| CPU | 4 vCPU (QEMU/KVM) |
| RAM | 7.8 GB (Elastic heap 512 MB, free ~3 GB sau cài) |
| Disk | 158 GB (đã dùng ~43 GB) |
| Firewall | UFW, default deny incoming |

### 4.2 Cài Elastic 8.x repo

Dùng cơ chế `signed-by` (chuẩn mới, không dùng `apt-key` deprecated):

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

echo 'deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] \
https://artifacts.elastic.co/packages/8.x/apt stable main' \
  | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

sudo apt-get update
```

### 4.3 Elasticsearch — cài + heap 512 MB

```bash
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y elasticsearch
sudo tee /etc/elasticsearch/jvm.options.d/heap.options <<EOF
-Xms512m
-Xmx512m
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now elasticsearch
```

**Verify heap đã apply trên JVM đang chạy:**

```bash
sudo ps -p $(pgrep -f org.elasticsearch.bootstrap.Elasticsearch) -o args= \
  | tr ' ' '\n' | grep -E '^-Xm[sx]'
# → -Xms512m  -Xmx512m  ✅
```

**Default `elasticsearch.yml` 8.x đã secure-by-default** (không sửa thêm):

```yaml
xpack.security.enabled: true
xpack.security.enrollment.enabled: true
xpack.security.http.ssl.enabled: true          # self-signed certs auto-gen
xpack.security.transport.ssl.enabled: true
http.host: 0.0.0.0
cluster.initial_master_nodes: ["vps"]
```

### 4.4 Reset & lưu password `elastic`

```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -b -s
# → <ELASTIC_PASSWORD>  (lưu vào file, không paste vào báo cáo)

umask 077
printf '[elastic]\nusername=elastic\npassword=%s\nURL=https://43.228.215.234:9200\n' \
  "$ELASTIC_PASSWORD" > ~/elastic-credentials.txt
```

> 🔒 Credentials thực **không** xuất hiện trong báo cáo này — chỉ trong `/home/namth/elastic-credentials.txt` (chmod 600) trên VPS.

### 4.5 Kibana — cài + enrollment + bind 0.0.0.0

```bash
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y kibana

# Enrollment chuẩn 8.x — không hard-code password vào kibana.yml
TOKEN=$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)
sudo /usr/share/kibana/bin/kibana-setup --enrollment-token "$TOKEN"

# Bind public
sudo bash -c '
  if grep -q "^server.host:" /etc/kibana/kibana.yml; then
    sed -i "s|^server.host:.*|server.host: \"0.0.0.0\"|" /etc/kibana/kibana.yml
  else
    echo "server.host: \"0.0.0.0\"" >> /etc/kibana/kibana.yml
  fi'

sudo systemctl enable --now kibana
```

### 4.6 Logstash — cài + pipeline winlogbeat.conf

Cài service + viết pipeline tại `/etc/logstash/conf.d/winlogbeat.conf` (xem [`configs/winlogbeat.conf`](configs/winlogbeat.conf) trong repo).

**Validate trước restart** — không restart-rồi-mới-phát-hiện-config-sai:

```bash
sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
# → Configuration OK
```

Khởi động + enable:

```bash
sudo systemctl enable --now logstash
```

### 4.7 UFW — mở port theo nguyên tắc least-privilege

```bash
sudo ufw allow 5044/tcp comment "Logstash Beats input"
sudo ufw allow 5601/tcp comment "Kibana UI"
sudo ufw reload
```

UFW status:

```
22/tcp     ALLOW  Anywhere   # SSH
5044/tcp   ALLOW  Anywhere   # Logstash Beats input
5601/tcp   ALLOW  Anywhere   # Kibana UI
# 9200 KHÔNG mở — chỉ truy cập qua SSH tunnel khi cần
```

### 4.8 Verify cuối Pha 1

| Hạng mục | Kết quả |
|---|---|
| Elasticsearch active + enabled | ✅ |
| Kibana active + enabled, bind 0.0.0.0 | ✅ |
| Logstash active + enabled | ✅ |
| Heap ES 512 MB verified | ✅ |
| Pipeline Logstash `Configuration OK` | ✅ |
| Beats input listening `*:5044` | ✅ |
| Kibana từ external (Kali → VPS:5601) | ✅ HTTP 200 (0.14s) |
| Cluster health | ✅ green |
| Credentials chmod 600 | ✅ |

---

## 5. Pha 2 — Endpoint Telemetry (đang làm)

**Mục tiêu:** Sysmon + Winlogbeat trên Windows 10 ship event log vào `43.228.215.234:5044`.

### 5.1 Lý do chọn Sysmon + SwiftOnSecurity config

| Sự kiện | Windows native | Sysmon |
|---|---|---|
| Process creation kèm command-line đầy đủ | ⚠️ Phải bật audit policy, chỉ Security 4688 | ✅ Event 1, có hash + parent + user |
| Network connection (PID nào kết nối ra ngoài) | ❌ | ✅ Event 3 |
| DNS query | ❌ | ✅ Event 22 |
| File create + hash | ⚠️ Hạn chế | ✅ Event 11 + 15 |
| Registry modification | ❌ | ✅ Event 12/13/14 |

→ Sysmon là tiêu chuẩn de facto cho endpoint telemetry trong SOC.
→ **SwiftOnSecurity** = config Sysmon được cộng đồng SOC dùng nhiều nhất, đã loại noise event điển hình.

### 5.2 Trạng thái Pha 2

| Thành phần | Trạng thái |
|---|---|
| Pipeline Logstash sẵn sàng ở `:5044` | ✅ |
| Prompt cho Antigravity setup endpoint | ✅ chuẩn bị xong (xem `roadmap.md` §A.1) |
| Sysmon installed trên Win10 | ✅ Hoàn tất |
| Winlogbeat installed trên Win10 | ✅ Hoàn tất |
| Event đầu tiên xuất hiện trong ES | ✅ Hoàn tất (Logstash acked > 2000 events) |
| Index `winlogbeat-*` được tạo | ✅ Hoàn tất |

### 5.3 Chi tiết triển khai Endpoint

1. **Cài đặt Sysmon**:
   - Tải từ Sysinternals và giải nén vào [C:\Sysmon](file:///C:/Sysmon).
   - Sử dụng file cấu hình SwiftOnSecurity: `sysmonconfig-export.xml`.
   - Lệnh cài đặt: `Sysmon64.exe -accepteula -i sysmonconfig-export.xml` (chạy dưới quyền Administrator).
   - Kiểm tra dịch vụ `Sysmon64` hoạt động bình thường, startup mode `Automatic`.

2. **Cài đặt Winlogbeat**:
   - Tải phiên bản Winlogbeat 8.19.0.
   - Giải nén vào thư mục `C:\Program Files\Winlogbeat`.
   - Cấu hình [winlogbeat.yml](file:///C:/Program%20Files/Winlogbeat/winlogbeat.yml) để chuyển tiếp log về cổng Logstash `43.228.215.234:5044`.
   - Chạy kiểm tra cấu hình thành công:
     ```cmd
     .\winlogbeat.exe test config -e
     .\winlogbeat.exe test output -e
     ```
   - Đăng ký và khởi động dịch vụ Winlogbeat thành công.

3. **Kiểm tra hoạt động**:
   - File log [winlogbeat-20260625.ndjson](file:///C:/ProgramData/winlogbeat/Logs/winlogbeat-20260625.ndjson) ghi nhận:
     `"Connection to backoff(async(tcp://43.228.215.234:5044)) established"`
   - Ghi nhận metrics gửi đi thành công với số lượng sự kiện log đã ack đạt trên 2000.

---

## 6. Sự cố & xử lý đã ghi nhận

Phần này quan trọng cho recruiter — chứng minh năng lực debug, không phải "copy lệnh từ tutorial".

### 6.1 `debconf: unable to initialize frontend: Dialog/Readline` khi apt install qua SSH

**Nguyên nhân:** SSH không cấp pseudo-TTY → debconf fall back qua Teletype.
**Xử lý:** Đặt `DEBIAN_FRONTEND=noninteractive` cho các install sau Elasticsearch (Kibana, Logstash).

### 6.2 Auto-generated `elastic` password trôi qua scrollback

**Nguyên nhân:** Output cài Elastic in password chỉ một lần lúc post-install.
**Xử lý:** Re-issue password bằng tool chính thức: `elasticsearch-reset-password -u elastic -b -s`. Sau đó redirect vào file `chmod 600`.

### 6.3 Logstash log `Not eligible for data streams`

**Nguyên nhân:** Chỉ định `index => "winlogbeat-%{+YYYY.MM.dd}"` rõ ràng → Logstash buộc phải đi đường time-based index, không phải data stream.
**Xử lý:** Đây là hành vi **mong muốn** — pattern `winlogbeat-*` đúng theo yêu cầu báo cáo.

### 6.4 Logstash WARN `ssl_verification_mode disabled`

**Nguyên nhân:** Cert ES là self-signed; lab chấp nhận `ssl_verification_mode => none`.
**Khuyến nghị production:** Mount `/etc/elasticsearch/certs/http_ca.crt` vào Logstash truststore, đổi `ssl_verification_mode => full`. Chưa làm.

### 6.5 ⚠️ UFW chặn 5601 nhưng `curl` trên server vẫn HTTP 200

**Nguyên nhân:** Request loopback từ server tự gọi public IP của mình → traffic đi qua `lo`, **không** đi qua INPUT chain → UFW không thấy.
**Bài học:** *Test bảo mật firewall phải test từ MÁY KHÁC.* Đã chạy lại `curl` từ Kali → ban đầu 5601 chưa mở. Sau khi `ufw allow 5601` mới phản hồi 200.
**Ý nghĩa:** Chính xác là kiểu lỗi "tưởng đã pass test nhưng không". Lab dạy phải nghi ngờ chính kết quả test của mình.

### 6.6 Pending kernel upgrade trên Ubuntu 24.04

**Nguyên nhân:** Kernel 6.8.0-54 (running) ≠ kernel 6.8.0-124 (đã cài).
**Quyết định:** **Không** reboot trong khi đang setup — rớt SSH và service. Tất cả service đã `enable`, sau reboot sẽ tự lên. Reboot là quyết định ops, không phải side-effect apt.

---

## 7. Hardening đã áp dụng vs còn thiếu

| # | Hardening | Trạng thái |
|---|---|---|
| 1 | X-Pack Security ON (TLS internal) | ✅ Default 8.x |
| 2 | UFW default deny + explicit allow | ✅ |
| 3 | ES không expose `:9200` ra Internet | ✅ |
| 4 | Credentials chmod 600 | ✅ |
| 5 | `bootstrap.memory_lock: true` (heap pinned) | ❌ Chưa — lab nhỏ chưa cần |
| 6 | Kibana TLS (HTTPS frontend) | ❌ Đang HTTP plain |
| 7 | Beats input TLS (Logstash:5044) | ❌ Plain TCP |
| 8 | Logstash verify ES cert chain | ❌ `ssl_verification_mode: none` |
| 9 | Password manager / Vault | ❌ Plain text file |
| 10 | RBAC + Spaces trong Kibana | ❌ Chỉ `elastic` superuser |

Phần "còn thiếu" sẽ đề cập trong `roadmap.md` (Pha 6 mở rộng nếu còn thời gian).

---

## 8. Kỹ năng đã chứng minh tới hiện tại

| Domain | Kỹ năng | Bằng chứng |
|---|---|---|
| Linux SysAdmin | systemd, journal, apt signed-by, UFW, SSH | §4.2, §4.5, §4.7 |
| JVM tuning | Heap min/max via `jvm.options.d/` | §4.3 |
| TLS & PKI | Self-signed CA, enrollment flow | §4.3, §4.5 |
| Logstash DSL | input/filter/output, `translate` plugin, ECS v8 | `configs/winlogbeat.conf` |
| Firewall testing | Phân biệt loopback vs real external | §6.5 |
| Documentation | Cấu trúc 3 file report/roadmap/changelog | repo này |
| AI tooling | Claude Code (SSH automation) | toàn bộ Pha 1 |

---

## 9. Phụ lục — lệnh tham khảo

### 9.1 One-shot reproduce Pha 1

```bash
#!/usr/bin/env bash
set -euo pipefail

# Repo + prereqs
sudo apt-get update -qq && sudo apt-get install -y -qq \
  apt-transport-https wget gnupg curl ca-certificates
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] \
https://artifacts.elastic.co/packages/8.x/apt stable main' \
  | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt-get update -qq

# Elasticsearch + 512MB heap
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y elasticsearch
sudo tee /etc/elasticsearch/jvm.options.d/heap.options <<<'-Xms512m
-Xmx512m'
sudo systemctl daemon-reload && sudo systemctl enable --now elasticsearch
ELASTIC_PW=$(sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -b -s)
umask 077
printf '[elastic]\nusername=elastic\npassword=%s\nURL=https://%s:9200\n' \
  "$ELASTIC_PW" "$(hostname -I | awk '{print $1}')" > ~/elastic-credentials.txt

# Kibana
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y kibana
TOKEN=$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)
sudo /usr/share/kibana/bin/kibana-setup --enrollment-token "$TOKEN"
sudo sed -i 's|^#*\s*server.host:.*|server.host: "0.0.0.0"|' /etc/kibana/kibana.yml \
  || echo 'server.host: "0.0.0.0"' | sudo tee -a /etc/kibana/kibana.yml
sudo systemctl enable --now kibana

# Logstash + pipeline
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y logstash
sudo cp configs/winlogbeat.conf /etc/logstash/conf.d/winlogbeat.conf
sudo systemctl enable --now logstash

# UFW
sudo ufw allow 5044/tcp comment "Logstash Beats input"
sudo ufw allow 5601/tcp comment "Kibana UI"
sudo ufw reload

echo "Kibana → http://$(hostname -I | awk '{print $1}'):5601"
```

### 9.2 Health-check vận hành

```bash
# Service
for s in elasticsearch kibana logstash; do
  printf "%-15s active=%s enabled=%s\n" "$s" \
    "$(sudo systemctl is-active $s)" \
    "$(sudo systemctl is-enabled $s)"
done

# Port
sudo ss -tlnp | grep -E ':(5044|5601|9200|9300|9600)'

# Pipeline events counter
curl -s http://localhost:9600/_node/stats/events?pretty

# ES health
curl -sk -u elastic:<ELASTIC_PASSWORD> https://localhost:9200/_cluster/health?pretty

# Index winlogbeat-*
curl -sk -u elastic:<ELASTIC_PASSWORD> \
  "https://localhost:9200/_cat/indices/winlogbeat-*?v"
```

---

*Báo cáo này được cập nhật theo nguyên tắc "deploy-then-document" — chỉ ghi nhận những gì đã thực thi xong. Các pha sắp tới xem [`roadmap.md`](roadmap.md). Lịch sử thay đổi: [`CHANGELOG.md`](CHANGELOG.md).*
