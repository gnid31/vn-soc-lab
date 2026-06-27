# VN-SOC Lab — Báo cáo Dự án

> **Mô phỏng Security Operations Center quy mô doanh nghiệp Việt Nam**
> *End-to-end SIEM • Detection Engineering • Adversary Emulation • Incident Response*

---

## Thông tin nhanh

| Mục | Giá trị |
|---|---|
| Tên dự án | VN-SOC Lab |
| Tác giả | `gnid31` |
| Bắt đầu | 2026-06-23 |
| Cập nhật cuối | 2026-06-27 |
| Trạng thái | ✅ **9/9 phases hoàn tất** — lab end-to-end CV-ready |
| Repo | github.com/gnid31/vn-soc-lab (private) |
| Stack chính | Elastic 8.19.17 (ES + Kibana + Logstash), Sysmon v15, Winlogbeat 8.19.0, Filebeat 8.19.17, Suricata 8.0.5, Wazuh 4.9.2 full stack, scikit-learn 1.5.2 (Flask), n8n 1.74.1, TheHive 5.4.0 (Cassandra 4 + ES 7) |
| VMs | VPS (Elastic + ML + n8n + SOAR bridge), SOC-Tools (Suricata + DVWA + TheHive), SOC-Wazuh (Wazuh stack), Win10 (Sysmon + Winlogbeat + Wazuh Agent), Kali (attacker + analyst) |
| Detection rules | 9 (R1-R9) cover 9 MITRE techniques: T1003.001, T1059.001, T1071.001, T1083, T1110, T1190, T1547.001, T1595, T1595.002 |

> ⚠️ **Quy ước viết báo cáo này:** `report.md` CHỈ ghi lại những phần đã thực thi và verify thành công (nguyên tắc *deploy-then-document*). Kế hoạch các pha sắp tới nằm trong [`roadmap.md`](roadmap.md). Mỗi commit sửa file này đi kèm 1 dòng trong [`CHANGELOG.md`](CHANGELOG.md).

---

## Mục lục

0. [Trước khi bắt đầu — Prerequisites & cách đọc](#0-trước-khi-bắt-đầu)
1. [Tóm tắt điều hành](#1-tóm-tắt-điều-hành)
2. [Bối cảnh & mục tiêu](#2-bối-cảnh--mục-tiêu)
3. [Kiến trúc hệ thống](#3-kiến-trúc-hệ-thống)
4. [Pha 1 — SIEM Backend (hoàn tất)](#4-pha-1--siem-backend-hoàn-tất)
5. [Pha 2 — Endpoint Telemetry (hoàn tất)](#5-pha-2--endpoint-telemetry-hoàn-tất)
6. [Pha 3-9 — Tổng quan các pha mở rộng](#6-pha-3-9--tổng-quan-các-pha-mở-rộng)
7. [Sự cố & xử lý đã ghi nhận](#7-sự-cố--xử-lý-đã-ghi-nhận)
8. [Hardening đã áp dụng vs còn thiếu](#8-hardening-đã-áp-dụng-vs-còn-thiếu)
9. [Kỹ năng đã chứng minh tới hiện tại](#9-kỹ-năng-đã-chứng-minh-tới-hiện-tại)
10. [Phụ lục — lệnh tham khảo](#10-phụ-lục--lệnh-tham-khảo)
11. [File Inventory — toàn bộ file đã sửa/tạo](#11-file-inventory)
12. [Troubleshooting flow](#12-troubleshooting-flow)

---

## 0. Trước khi bắt đầu

### 0.1 Cách đọc báo cáo

Báo cáo này được tổ chức theo **dòng chảy triển khai thực tế**, không phải theo sách giáo khoa. Người đọc nên đi theo thứ tự:

1. **§0 Prerequisites** → đảm bảo có đủ tài nguyên & tài khoản.
2. **§3 Kiến trúc** → hình dung toàn cảnh trước khi gõ lệnh.
3. **§4 Pha 1** → dựng SIEM backend (mất ~45–60 phút).
4. **§5 Pha 2** → cài endpoint Windows (mất ~30 phút).
5. **§6 Sự cố** → tham khảo khi gặp lỗi.
6. **§11 Troubleshooting** → flowchart debug nhanh.

Mọi command-block đều có thể copy-paste **nguyên si**. Mọi placeholder `<...>` đều có thể thay bằng giá trị thực.

### 0.2 Prerequisites — phải có trước khi triển khai

#### A. Hạ tầng vật lý

| Thành phần | Yêu cầu tối thiểu | Khuyến nghị | Ghi chú |
|---|---|---|---|
| **VPS Cloud** (SIEM) | 2 vCPU, 4 GB RAM, 40 GB disk | 4 vCPU, 8 GB RAM, 100+ GB | Public IPv4. ES single-node + Kibana + Logstash chia sẻ. Lab này dùng VPS cụ thể `43.228.215.234` |
| **Endpoint Windows** | Win10 1909+, 2 GB RAM | Win10 22H2, 4 GB RAM | Có thể là máy thật hoặc VM. Sysmon + Winlogbeat ngốn ~200–400 MB |
| **Workstation** | bất kỳ OS có browser + SSH client | Kali Linux (cho automation) | Để truy cập Kibana UI + SSH vào VPS |

#### B. Network access

| Hướng | Port | Mục đích |
|---|---|---|
| Internet → VPS | 22/tcp | SSH |
| Internet → VPS | 5601/tcp | Kibana UI (HTTP plain trong lab — production phải HTTPS) |
| Endpoint Win10 → VPS | 5044/tcp | Beats Lumberjack (Winlogbeat → Logstash) |
| Internet → VPS | **KHÔNG mở 9200** | Elasticsearch HTTPS — chỉ loopback |

Nếu VPS provider có security group / network firewall riêng (DigitalOcean, AWS, Vultr...), mở 3 port `22, 5044, 5601` trước khi vào UFW.

#### C. Tài khoản & token cần chuẩn bị

| Service | Mục đích | Cách lấy |
|---|---|---|
| **GitHub** (đã có: `gnid31`) | Repo `vn-soc-lab` private — version control + collab giữa 2 AI | https://github.com/signup |
| **Anthropic API key** | Claude Code CLI trên Kali tự động hoá SSH | https://console.anthropic.com/settings/keys |
| **Antigravity (Google) hoặc tool tương đương** | Cài Sysmon/Winlogbeat trên Win10 (PowerShell agent) | https://antigravity.google/ |

#### D. Tool cần cài trước trên Workstation (Kali)

```bash
# CLI tools
sudo apt-get install -y sshpass openssl curl wget git python3 unzip

# GitHub CLI (không có trong repo Kali default — phải add upstream)
wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
  | sudo tee /etc/apt/sources.list.d/github-cli.list
sudo apt-get update && sudo apt-get install -y gh

# Login GitHub
gh auth login                # → GitHub.com → HTTPS → web browser device flow
gh auth setup-git            # hook gh credentials vào git native
```

#### E. Tool cần cài trên Endpoint Win10

```powershell
# PowerShell as Administrator
# Git for Windows (nếu repo cần thao tác local)
winget install --id Git.Git -e

# GitHub CLI (nếu Antigravity dùng git)
winget install --id GitHub.cli -e
gh auth login    # cùng flow như Kali

# Sysmon + Winlogbeat tải qua URL ở §5 — không cần winget
```

#### F. Kiến thức nền tối thiểu

- Linux: `systemctl`, `journalctl`, `ufw`, edit file `/etc/...`, SSH key/password.
- Windows: PowerShell as Administrator, Get-Service, Get-WinEvent.
- Networking: hiểu port, loopback (`lo`) vs interface ngoài, TCP connect.
- Đọc được YAML, JSON, KQL.

### 0.3 Các lệnh quy ước trong báo cáo

| Ký hiệu | Nghĩa |
|---|---|
| `sudo …` | Chạy trên VPS, cần root |
| `gh …` / `git …` | Chạy trên Kali (workstation) |
| `PS> …` | Chạy trên Win10, PowerShell as Administrator |
| `<ELASTIC_PASSWORD>` | Placeholder — giá trị thực lưu tại `/home/namth/elastic-credentials.txt` chmod 600 trên VPS |
| `43.228.215.234` | Public IP VPS lab này — thay thành IP VPS của bạn khi reproduce |
| `DESKTOP-L7FCMBQ` | Hostname endpoint Win10 lab này — thay thành hostname của bạn |

---

## 1. Tóm tắt điều hành

**Đến thời điểm cập nhật cuối (2026-06-27)**, dự án đã hoàn tất **9/9 pha** — lab CV-ready, mô phỏng đầy đủ vòng đời SOC từ collection → detection → response → automation:

| Pha | Tên | Trạng thái | Deliverable chính |
|---|---|---|---|
| 1 | SIEM Backend | ✅ | Elastic 8.19 (ES + Kibana + Logstash) trên VPS 43.228.215.234 |
| 2 | Endpoint Telemetry | ✅ | Sysmon + Winlogbeat trên Win10 → 4400+ event/day |
| 3 | Detection Engineering (R1-R5) | ✅ | 5 KQL rule MITRE-mapped (T1003/T1059/T1110/T1547/T1071) |
| 4 | Adversary Emulation | ✅ | Atomic Red Team chain T1547→T1059→T1110, 5 lessons + R5 FP tune |
| 5 | Incident Response | ✅ | VN-SOC-2026-0001 kill-chain doc NIST 800-61 format |
| 6 | Network IDS Layer (R6-R8) | ✅ | Suricata 8.0.5 + DVWA + 3 rule (T1595/T1595.002/T1083) |
| 7 | Wazuh HIDS Full Stack | ✅ | Multi-SIEM: Wazuh Manager + Indexer + Dashboard + Win10 Agent |
| 8 | ML Detection (R9) | ✅ | TF-IDF + LogReg URL classifier, Flask Docker, Logstash enrichment |
| 9 | SOAR & Case Management | ✅ | TheHive 5 + n8n + alert bridge → 34 cases auto |
| 9.5 | Cortex Analyzer Integration | ✅ | Cortex 3.1.7 + VT + AbuseIPDB → TheHive observables auto-enrich |

**Stack đang chạy:**

```
                 KALI (attacker + analyst host)
                       │  curl DVWA / Atomic Red Team
                       │  autossh reverse tunnels VPS↔SOC-Tools
                       │  SSH local forwards cho Kibana / n8n / TheHive UI
                       │
       LOCAL VMware NAT vmnet8 (192.168.154.0/24):
         Win10 victim   192.168.154.164  Sysmon + Winlogbeat + Wazuh Agent
         SOC-Tools VM   192.168.154.165  Suricata + DVWA + TheHive stack
         SOC-Wazuh VM   192.168.154.163  Wazuh Manager + Indexer + Dashboard

                       │ ship logs (Beats / Wazuh proto / agent enrollment)
                       ▼

       VPS 43.228.215.234 — central SIEM + SOAR plane:
         Elastic 8.19   ES :9200 / Kibana :5601 / Logstash :5044
           indices: winlogbeat-* | suricata-* | dvwa-apache-*
         ML Detection   Flask URL classifier Docker :5000 loopback
         SOAR           n8n :5678 (host network) + systemd timer poll ES → n8n
                        → SSH reverse tunnel → TheHive :9000 case auto
```

**Truy cập (cuối Pha 9):**

| Endpoint | URL/Port | Trạng thái |
|---|---|---|
| Kibana UI | http://43.228.215.234:5601 | ✅ HTTP 200 external |
| Wazuh Dashboard | https://192.168.154.163 | ✅ admin login + 2 agents active |
| TheHive 5 UI | http://192.168.154.165:9000 (via SSH tunnel) | ✅ 34 cases auto-created |
| n8n workflow editor | http://127.0.0.1:5678 (via SSH local forward) | ✅ workflow Active |
| Flask ML API | http://127.0.0.1:5000 (loopback VPS) | ✅ /health + /predict |
| ES indices | winlogbeat-* / suricata-* / dvwa-apache-* | ✅ multi-source ingest |
| Detection rules | 9 enabled (R1-R9) | ✅ verified Pha 3-8 |

---

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
| 2 | Endpoint Windows ship log | ✅ Sysmon + Winlogbeat đẩy event vào `winlogbeat-*` |
| 3 | Detection rule mapping MITRE | 🔄 Pha 3 (R1 spec sẵn sàng) |
| 4 | Adversary emulation | ⏳ Pha 4 |
| 5 | Incident Report mẫu | ⏳ Pha 5 |
| 6 | Document trade-off bảo mật | 🔄 cập nhật theo từng pha |

### 2.3 Phạm vi & ngoài phạm vi

- **Trong phạm vi:** Detection thuần (defensive), 1 endpoint Windows, 1 SIEM single-node.
- **Ngoài phạm vi:** SOAR đầy đủ, malware reverse engineering, compliance audit (PCI-DSS, ISO 27001), cluster ES nhiều node.

---

## 3. Kiến trúc hệ thống

### 3.1 Sơ đồ tổng thể

```
                       ┌──────────────────────────────────────────────┐
                       │             ANALYST WORKSTATION              │
                       │  (browser + SSH client — Kali hoặc Windows) │
                       └──────────┬──────────────────────┬────────────┘
                                  │ HTTP 5601            │ SSH 22
                                  ↓                      ↓
              ╔═══════════════════════════════════════════════════════╗
              ║          VPS Cloud — 43.228.215.234 (Ubuntu 24.04)   ║
              ║                                                       ║
              ║  ┌──────────────────────────────────────────────┐    ║
              ║  │ Kibana 8.19.17 (0.0.0.0:5601) — Web UI       │    ║
              ║  │ + keystore: 3 encryption keys cho Alerts/    │    ║
              ║  │   Detection Engine (xpack.encryptedSaved...)  │    ║
              ║  └────────────────────┬─────────────────────────┘    ║
              ║                       │ HTTPS 9200 (loopback only)   ║
              ║                       ↓                              ║
              ║  ┌──────────────────────────────────────────────┐    ║
              ║  │ Elasticsearch 8.19.17                        │    ║
              ║  │ - heap 512 MB (lab) / 4-8 GB (production)    │    ║
              ║  │ - X-Pack Security ON (TLS self-signed)       │    ║
              ║  │ - index: winlogbeat-YYYY.MM.dd               │    ║
              ║  │ - alerts: .internal.alerts-security.*        │    ║
              ║  └──────────────────────────────────────────────┘    ║
              ║                       ↑                              ║
              ║                       │ HTTPS 9200 (loopback)        ║
              ║  ┌──────────────────────────────────────────────┐    ║
              ║  │ Logstash 8.19.17                             │    ║
              ║  │ - Pipeline: configs/winlogbeat.conf          │    ║
              ║  │   ├── Input: beats { port => 5044 }          │    ║
              ║  │   ├── Filter:                                │    ║
              ║  │   │   ├── date normalize @timestamp          │    ║
              ║  │   │   ├── add event.provider                 │    ║
              ║  │   │   ├── if Sysmon → translate event_id +   │    ║
              ║  │   │   │   tag "sysmon", event.category=sysmon │    ║
              ║  │   │   ├── elif Security → translate 4624/.../│    ║
              ║  │   │   │   tag "security", category=auth      │    ║
              ║  │   │   ├── elif System/App → tag windows_*    │    ║
              ║  │   │   └── elif PowerShell → tag powershell   │    ║
              ║  │   └── Output: ES https://localhost:9200      │    ║
              ║  │       + fallback logstash-* cho non-winlogbeat│   ║
              ║  └──────────────────────┬───────────────────────┘    ║
              ║                         ↑                            ║
              ║                         │ TCP 5044 (Lumberjack)      ║
              ║         UFW: allow 22, 5044, 5601 (9200 deny)        ║
              ╚═════════════════════════│════════════════════════════╝
                                        │ Public Internet
                                        ↓
                ╔════════════════════════════════════════════════════╗
                ║   ENDPOINT — Windows 10  DESKTOP-L7FCMBQ          ║
                ║                                                    ║
                ║   ┌─────────────────────────────────────────┐     ║
                ║   │ Sysmon v15 + SwiftOnSecurity config     │     ║
                ║   │ Channel: Microsoft-Windows-Sysmon/      │     ║
                ║   │          Operational                    │     ║
                ║   │ Generated events (mẫu 24h):             │     ║
                ║   │   e1=process_creation, e3=network,      │     ║
                ║   │   e11=file_create, e13=registry,        │     ║
                ║   │   e22=dns_query                         │     ║
                ║   └────────────────┬────────────────────────┘     ║
                ║                    │                              ║
                ║   ┌────────────────▼────────────────────────┐     ║
                ║   │ Winlogbeat 8.19.0 service               │     ║
                ║   │ Channels collected:                     │     ║
                ║   │   • Application                         │     ║
                ║   │   • System                              │     ║
                ║   │   • Security                            │     ║
                ║   │   • Microsoft-Windows-Sysmon/Operational│     ║
                ║   │   • Microsoft-Windows-PowerShell/Op.    │     ║
                ║   │ Output: logstash 43.228.215.234:5044    │     ║
                ║   │ Tags:   vn-soc-lab, endpoint-win10,     │     ║
                ║   │         <HOSTNAME>                       │     ║
                ║   └─────────────────────────────────────────┘     ║
                ╚════════════════════════════════════════════════════╝
```

### 3.2 Quyết định thiết kế chính & lý do

**Quyết định 1 — Bare-metal thay vì Docker.**

Lab này dựng ES/Kibana/Logstash thẳng lên Ubuntu (apt package + systemd service), KHÔNG dùng `docker-compose`. Lý do:

- Hiểu sâu hơn về cấu hình heap JVM, X-Pack security default, certs tự sinh.
- Khi phỏng vấn SOC: trả lời được câu *"giải thích process khi bạn cài Elasticsearch?"* tốt hơn so với *"tôi chạy docker compose up"*.
- Lab 1 node, 1 service mỗi loại → không lợi ích hơn từ container.

**Quyết định 2 — Tách Logstash khỏi port ES public.**

Winlogbeat KHÔNG nói thẳng với `:9200`. Mọi event đều qua Logstash `:5044`. Lý do:

| Lý do | Chi tiết |
|---|---|
| Tách trách nhiệm | Logstash = normalize/enrich; Beats = transport |
| Bảo mật firewall | `:9200` đóng kín, không có index API public — kẻ tấn công không brute-force được |
| Enrich tập trung | Sau thêm Wazuh/Suricata cùng đi qua 1 pipeline → 1 chỗ thêm threat intel lookup |
| Backpressure | Persistent queue ở Logstash → ES sập không mất event của Beats |

**Quyết định 3 — Heap ES = 512 MB.**

VPS chỉ 7.8 GB RAM, lab nhỏ < 2 GB index/ngày. Quy tắc Elastic: heap ≤ 50% RAM, cap ~30 GB. 512 MB đủ cho 1 node single-shard lab. Production cùng workload phải 2–4 GB.

**Quyết định 4 — Self-signed TLS cho ES, `ssl_verification_mode: none` ở Logstash.**

Elastic 8.x auto-sinh self-signed CA. Lab chấp nhận skip verify để tiết kiệm thời gian distribute CA cert. Sản xuất: `verification_mode: full` + mount `/etc/elasticsearch/certs/http_ca.crt`.

---

## 4. Pha 1 — SIEM Backend (hoàn tất)

**Hoàn tất:** 2026-06-25
**Mục tiêu:** Cài Elasticsearch + Kibana + Logstash 8.x trên VPS, bind Kibana public, enable auto-start, hardening cơ bản, **đầy đủ encryption keys** cho Detection Engine.

### 4.1 VPS spec (xác nhận tối thiểu)

| | |
|---|---|
| OS | Ubuntu 24.04.2 LTS (Noble) |
| CPU | 4 vCPU (QEMU/KVM) |
| RAM | 7.8 GB (Elastic heap 512 MB, free ~3 GB sau cài) |
| Disk | 158 GB (đã dùng ~43 GB sau cài + 4400 docs) |
| Firewall | UFW, default deny incoming |
| Swap | 0 B (Elastic khuyến nghị tắt — đã tự đáp ứng) |

### 4.2 Linux pre-check trước khi cài Elasticsearch

ES 8.x package auto-set các kernel parameter cần thiết, nhưng nên **verify** trước khi cài để bắt sớm lỗi sysctl:

```bash
# vm.max_map_count — Elasticsearch yêu cầu ≥ 262144 (default Ubuntu 24.04 đã đủ)
sysctl vm.max_map_count
#   → vm.max_map_count = 262144      ✅

# ulimit file descriptor — ES service tự đặt LimitNOFILE=65535 qua systemd
# Check sau khi cài: 
#   systemctl show elasticsearch -p LimitNOFILE

# Swap nên = 0 hoặc bật memory_lock — VPS này swap=0 ✅
swapon --show     # rỗng = không có swap = ok cho lab

# Disk free ≥ 20 GB (ES có disk watermark default 85% — chật sẽ read-only)
df -h /
#   → /dev/sda2  158G  43G  109G  29%  /     ✅
```

Nếu `vm.max_map_count` thấp:

```bash
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.d/99-elasticsearch.conf
sudo sysctl --system
```

### 4.3 Thêm Elastic 8.x APT repo

Dùng cơ chế `signed-by` (chuẩn mới, không dùng `apt-key` deprecated):

```bash
sudo apt-get update -qq
sudo apt-get install -y -qq apt-transport-https wget gnupg curl ca-certificates

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

echo 'deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] \
https://artifacts.elastic.co/packages/8.x/apt stable main' \
  | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

sudo apt-get update -qq
```

### 4.4 Cài Elasticsearch + heap 512 MB

```bash
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y elasticsearch
```

**`DEBIAN_FRONTEND=noninteractive`** tránh debconf bung Dialog/Readline warning khi cài qua SSH (đã ghi nhận ở §6.1).

**Heap override — best practice 8.x:** dùng file riêng trong `jvm.options.d/` thay vì sửa `jvm.options` chính (giúp upgrade không bị overwrite):

```bash
sudo tee /etc/elasticsearch/jvm.options.d/heap.options <<EOF
-Xms512m
-Xmx512m
EOF
```

**Khởi động + enable auto-start:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now elasticsearch
sudo systemctl is-active elasticsearch    # → active
```

**Verify heap đã apply trên JVM đang chạy** (đừng tin file, tin process):

```bash
sudo ps -p $(pgrep -f org.elasticsearch.bootstrap.Elasticsearch) -o args= \
  | tr ' ' '\n' | grep -E '^-Xm[sx]'
# → -Xms512m  -Xmx512m  ✅
```

**Default `/etc/elasticsearch/elasticsearch.yml` 8.x đã secure-by-default** — không sửa thêm:

```yaml
xpack.security.enabled: true
xpack.security.enrollment.enabled: true
xpack.security.http.ssl:
  enabled: true
  keystore.path: certs/http.p12          # self-signed, auto-gen lúc install
xpack.security.transport.ssl:
  enabled: true
  verification_mode: certificate
  keystore.path: certs/transport.p12
  truststore.path: certs/transport.p12
http.host: 0.0.0.0
cluster.initial_master_nodes: ["vps"]    # tên VPS hostname
```

### 4.5 Reset & lưu password `elastic`

Auto-generated password được in chỉ 1 lần trong post-install — dễ trôi qua scrollback. Cách an toàn: re-issue ngay:

```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -b -s
# -b = batch (no prompt), -s = silent (chỉ in password to stdout)
# Output ví dụ: <ELASTIC_PASSWORD_32_CHARS>  → lưu NGAY vào file
```

**Lưu credentials chmod 600** (chỉ user `namth` đọc):

```bash
umask 077    # file mới mặc định mode 600
cat > ~/elastic-credentials.txt <<EOF
# Elastic Stack Credentials — VN-SOC Lab
[elastic superuser]
username = elastic
password = <ELASTIC_PASSWORD>
URL      = https://43.228.215.234:9200
EOF
chmod 600 ~/elastic-credentials.txt
```

> 🔒 Credentials thực **không** xuất hiện trong báo cáo này — chỉ trong `/home/namth/elastic-credentials.txt` (chmod 600) trên VPS và `~/.secrets/credentials.md` (chmod 600) trên Kali workstation.

**Verify ES respond:**

```bash
PASSWORD=$(grep '^password' ~/elastic-credentials.txt | cut -d= -f2 | tr -d ' ')
curl -sk -u "elastic:$PASSWORD" https://localhost:9200/_cluster/health
# → {"cluster_name":"elasticsearch","status":"green",...}
```

### 4.6 Cài Kibana + enrollment + bind 0.0.0.0

```bash
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y kibana
```

**Enrollment chuẩn 8.x** — không hard-code password ES vào `kibana.yml` (Kibana keystore tự nhận):

```bash
# Trên ES: tạo enrollment token (TTL ~30 phút)
TOKEN=$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)

# Hand sang Kibana — auto-write CA fingerprint + kibana_system credentials vào keystore
sudo /usr/share/kibana/bin/kibana-setup --enrollment-token "$TOKEN"
# → "✔ Kibana configured successfully."
```

**Bind `0.0.0.0`** (mặc định Kibana 8.x chỉ bind `localhost`):

```bash
sudo bash -c '
  if grep -q "^server.host:" /etc/kibana/kibana.yml; then
    sed -i "s|^server.host:.*|server.host: \"0.0.0.0\"|" /etc/kibana/kibana.yml
  else
    echo "server.host: \"0.0.0.0\"" >> /etc/kibana/kibana.yml
  fi'
```

### 4.7 Kibana keystore — encryption keys cho Detection Engine ⚠️

**BƯỚC NÀY THƯỜNG BỊ BỎ SÓT** trong tutorial Kibana 8.x. Bỏ qua sẽ dẫn tới lỗi **"Detection engine permissions required"** (sai message — thật ra do thiếu encryption keys, không phải permission — xem [§7.7](#77-kibana-detection-engine-báo-permissions-required-thực-ra-thiếu-encryption-keys)).

Detection Engine, Alerts, Actions, Fleet đều cần **3 encryption key** để encrypt API tokens / rule secrets / saved objects:

| Setting | Mục đích |
|---|---|
| `xpack.encryptedSavedObjects.encryptionKey` | Encrypt saved objects (alert configs, action credentials) |
| `xpack.reporting.encryptionKey` | Encrypt PDF/CSV reporting jobs |
| `xpack.security.encryptionKey` | Encrypt session cookies |

**Sinh 3 random 256-bit key + add vào keystore (encrypted at rest):**

```bash
KEY_SAVED=$(openssl rand -hex 32)
KEY_REPORTING=$(openssl rand -hex 32)
KEY_SECURITY=$(openssl rand -hex 32)

printf '%s' "$KEY_SAVED"     | sudo /usr/share/kibana/bin/kibana-keystore add \
  --stdin xpack.encryptedSavedObjects.encryptionKey
printf '%s' "$KEY_REPORTING" | sudo /usr/share/kibana/bin/kibana-keystore add \
  --stdin xpack.reporting.encryptionKey
printf '%s' "$KEY_SECURITY"  | sudo /usr/share/kibana/bin/kibana-keystore add \
  --stdin xpack.security.encryptionKey

# Verify keystore (chỉ in tên key, không in value):
sudo /usr/share/kibana/bin/kibana-keystore list
# → xpack.encryptedSavedObjects.encryptionKey
#   xpack.reporting.encryptionKey
#   xpack.security.encryptionKey
```

> 🔐 **Bảo mật:** lưu keys vào keystore an toàn hơn `kibana.yml` (file plain text). Nếu mất keys, không decrypt được saved objects — phải restore từ backup. **Backup keystore file `/etc/kibana/kibana.keystore` cùng với data**.

### 4.8 Cài Logstash

```bash
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y logstash
```

Default config tại `/etc/logstash/logstash.yml` (không sửa).

### 4.9 Pipeline `winlogbeat.conf` — giải thích filter chain

**File:** `/etc/logstash/conf.d/winlogbeat.conf` (138 dòng — bản đầy đủ trong [`configs/winlogbeat.conf`](configs/winlogbeat.conf)).

**Cấu trúc 3 block:**

```ruby
input  { beats { port => 5044 } }    # Lumberjack protocol từ Winlogbeat
filter { … }                          # Normalize + enrich
output { elasticsearch { … } }       # Đẩy vào ES với index theo ngày
```

**Logic filter chain (theo thứ tự):**

```
event vào
   │
   ├── [agent.type == "winlogbeat"]?  ── KHÔNG ──> bỏ qua filter, fallback output
   │       ↓ CÓ
   │
   ├── date normalize: @timestamp = winlog.time_created (ISO8601)
   │   (mặc định @timestamp = lúc Logstash NHẬN, không phải lúc Windows TẠO — fix)
   │
   ├── add event.provider = winlog.provider_name
   │
   ├── BRANCH 1 — Sysmon (winlog.provider_name == "Microsoft-Windows-Sysmon"):
   │       ├── add_tag "sysmon"
   │       ├── translate winlog.event_id (1..29) → event.action
   │       │   (e1 → "process_creation", e3 → "network_connection",
   │       │    e11 → "file_create", e13 → "registry_value_set",
   │       │    e22 → "dns_query", v.v.)
   │       └── add event.category = "sysmon"
   │
   ├── BRANCH 2 — Security channel:
   │       ├── add_tag "security"
   │       ├── translate winlog.event_id (4624, 4625, 4688, 4720, ...) →
   │       │   event.action ("logon_success", "logon_failed", "process_created",
   │       │   "user_account_created", ...)
   │       └── add event.category = "authentication"
   │
   ├── BRANCH 3 — System / Application channel:
   │       └── add_tag "windows_event_log"
   │
   ├── BRANCH 4 — PowerShell channel:
   │       ├── add_tag "powershell"
   │       └── add event.category = "process"
   │
   └── add host.hostname = host.name  (utility field, dễ KQL hơn)

event ra
   │
   ├── [agent.type == "winlogbeat"]? → ES index winlogbeat-YYYY.MM.dd (action: create)
   └── else → ES index logstash-YYYY.MM.dd (fallback debug)
```

**Vì sao 4 branch tách rời `else if`:**

- Mỗi event Sysmon chỉ thuộc 1 provider duy nhất → exclusive branches.
- Tag-by-tag giúp Kibana lọc nhanh: `tags: "sysmon"` ngắn hơn nhiều so với `winlog.provider_name: "Microsoft-Windows-Sysmon"`.
- `event.action` đã ECS-mapped → KQL `event.action: process_creation` thay vì nhớ `event_id: 1`.

**Copy file lên server + validate trước restart:**

```bash
# Từ Kali workstation (giả sử repo clone tại ~/Documents/vn-soc-lab):
sshpass -p '<VPS_SSH_PASS>' scp ~/Documents/vn-soc-lab/configs/winlogbeat.conf \
  namth@43.228.215.234:/tmp/winlogbeat.conf

# Trên VPS:
sudo install -o root -g root -m 0644 \
  /tmp/winlogbeat.conf /etc/logstash/conf.d/winlogbeat.conf

# Thay placeholder <ELASTIC_PASSWORD> bằng giá trị thực:
sudo sed -i "s|<ELASTIC_PASSWORD>|$(grep '^password' ~/elastic-credentials.txt | cut -d= -f2 | tr -d ' ')|g" \
  /etc/logstash/conf.d/winlogbeat.conf

# Validate cú pháp TRƯỚC khi restart (tránh service chết khi restart):
sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
# → Configuration OK     ✅
```

**Khởi động + enable:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now logstash
sudo systemctl is-active logstash    # → active
```

### 4.10 UFW — mở port theo least-privilege

```bash
sudo ufw allow 22/tcp   comment "SSH"                         # nếu chưa có
sudo ufw allow 5044/tcp comment "Logstash Beats input"
sudo ufw allow 5601/tcp comment "Kibana UI"
sudo ufw reload
sudo ufw status verbose
```

Kết quả:

```
22/tcp     ALLOW IN    Anywhere         # SSH
5044/tcp   ALLOW IN    Anywhere         # Logstash Beats input
5601/tcp   ALLOW IN    Anywhere         # Kibana UI
# 9200 KHÔNG mở — chỉ loopback. Truy cập từ workstation qua SSH tunnel:
#   ssh -L 9200:localhost:9200 namth@43.228.215.234
```

### 4.11 Verify cuối Pha 1

```bash
# All 3 service active + enabled
for s in elasticsearch kibana logstash; do
  printf "%-15s active=%s enabled=%s\n" "$s" \
    "$(sudo systemctl is-active $s)" \
    "$(sudo systemctl is-enabled $s)"
done
# elasticsearch  active=active  enabled=enabled
# kibana         active=active  enabled=enabled
# logstash       active=active  enabled=enabled

# Port listening
sudo ss -tlnp | grep -E ':(5044|5601|9200|9300|9600)'
# *:5044        — Beats input
# 0.0.0.0:5601  — Kibana
# *:9200        — Elasticsearch HTTPS
# [::1]:9300    — ES transport (loopback)
# 127.0.0.1:9600— Logstash monitoring API

# Cluster health
PASSWORD=$(grep '^password' ~/elastic-credentials.txt | cut -d= -f2 | tr -d ' ')
curl -sk -u "elastic:$PASSWORD" https://localhost:9200/_cluster/health?pretty
# status: "green"

# Kibana reachable từ external (chạy từ Kali, KHÔNG chạy trên VPS):
curl -s -o /dev/null -w 'HTTP %{http_code}\n' http://43.228.215.234:5601/api/status
# HTTP 200

# Kibana keystore có 3 key chưa:
sudo /usr/share/kibana/bin/kibana-keystore list
# xpack.encryptedSavedObjects.encryptionKey
# xpack.reporting.encryptionKey
# xpack.security.encryptionKey
```

| Hạng mục | Kết quả |
|---|---|
| Elasticsearch active + enabled | ✅ |
| Kibana active + enabled, bind 0.0.0.0 | ✅ |
| Logstash active + enabled | ✅ |
| Heap ES 512 MB (verify on JVM) | ✅ |
| Pipeline Logstash validate `Configuration OK` | ✅ |
| Beats input listening `*:5044` | ✅ |
| Kibana từ external (Kali → VPS:5601) | ✅ HTTP 200 (~0.14s) |
| Cluster health | ✅ green |
| Kibana keystore có 3 encryption keys | ✅ |
| Credentials chmod 600 | ✅ |

---

## 5. Pha 2 — Endpoint Telemetry (hoàn tất)

**Hoàn tất:** 2026-06-25 (qua Antigravity trên Win10, verified từ VPS)
**Mục tiêu:** Sysmon + Winlogbeat trên Windows 10 ship event log vào `43.228.215.234:5044`.

### 5.1 Lý do chọn Sysmon + SwiftOnSecurity config

| Sự kiện | Windows native log | Sysmon |
|---|---|---|
| Process creation kèm command-line đầy đủ | ⚠️ Phải bật audit policy, chỉ Security 4688 | ✅ Event 1 — có hash MD5/SHA256, parent process, user |
| Network connection (PID nào kết nối ra ngoài) | ❌ Không có | ✅ Event 3 |
| DNS query | ❌ (chỉ nếu bật DNS Client log) | ✅ Event 22 |
| File create + hash | ⚠️ Hạn chế | ✅ Event 11 (create) + 15 (file_create_stream_hash) |
| Registry modification | ❌ | ✅ Event 12 (create/delete), 13 (set value), 14 (rename) |
| Process access (LSASS-style) | ❌ | ✅ Event 10 |

→ Sysmon là **tiêu chuẩn de facto** cho endpoint telemetry trong SOC.
→ **SwiftOnSecurity config** = file XML mở rộng của cộng đồng, đã loại noise event điển hình (vd background scheduler, telemetry MS), giữ lại event có giá trị detection.

### 5.2 Prompt sử dụng với Antigravity (Google AI agent) trên Win10 — TÙY CHỌN

Antigravity chạy as Administrator trên Win10 sẽ thực hiện toàn bộ install + cấu hình. Prompt không chứa credential Elastic — Winlogbeat chỉ nói với Logstash:5044, không cần password.

> 🔧 **Reproducibility without AI:** Nếu bạn không có Antigravity hoặc không muốn dùng AI agent, **bỏ qua phần prompt dưới** và làm trực tiếp 2 bước manual:
> 1. **§5.3** — install Sysmon (PowerShell native commands, copy-paste).
> 2. **§5.4** — install Winlogbeat + cấu hình `winlogbeat.yml` (đã có YAML đầy đủ inline).
>
> Cả 2 bước manual đó **tương đương** với mọi thứ trong prompt Antigravity. Mục đích section này chỉ để document cách team original dùng AI accelerator.

````
Hãy cài và cấu hình Sysmon + Winlogbeat trên máy Windows 10 này
để ship log về VN-SOC Lab.

THÔNG SỐ LAB:
- Logstash Beats input: 43.228.215.234:5044   (TCP, không TLS phía Beats)
- KHÔNG dùng output.elasticsearch — lab này thu mọi log qua Logstash
  để enrich & normalize tập trung. Output Winlogbeat phải là output.logstash.

THỰC HIỆN THEO THỨ TỰ:

[1] Sysmon (Microsoft Sysinternals)
   - URL Sysmon: https://download.sysinternals.com/files/Sysmon.zip
   - Giải nén vào C:\Sysmon
   - URL config SwiftOnSecurity:
     https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
   - Cài: Sysmon64.exe -accepteula -i sysmonconfig-export.xml
   - Verify: Get-Service Sysmon64    # Status=Running, StartType=Automatic
   - Verify event đang sinh:
     Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5

[2] Winlogbeat 8.x (PHẢI khớp major.minor với Elastic — lab dùng 8.19)
   - URL: https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.19.0-windows-x86_64.zip
   - Giải nén vào "C:\Program Files\Winlogbeat"

[3] Ghi đè file winlogbeat.yml (backup file cũ thành winlogbeat.yml.bak trước):

(nội dung winlogbeat.yml — xem §5.4)

   Trước khi save: thay <HOSTNAME> bằng $env:COMPUTERNAME thực tế.

[4] Test config syntax:
   cd "C:\Program Files\Winlogbeat"
   .\winlogbeat.exe test config -e
   .\winlogbeat.exe test output -e
   Cả hai PHẢI trả về "OK" mới sang bước 5.

[5] Đăng ký Winlogbeat thành Windows service (PowerShell as Administrator):
   .\install-service-winlogbeat.ps1
   Start-Service winlogbeat
   Get-Service winlogbeat    # phải Running

[6] Sanity check end-to-end:
   - Trigger 1 process: notepad.exe → đóng
   - Đợi 30 giây
   - Tail log: Get-Content "C:\ProgramData\winlogbeat\Logs\winlogbeat" -Tail 30
   - PHẢI thấy: "Connection to backoff(async(tcp://43.228.215.234:5044)) established"

[7] Báo cáo lại:
   - Get-Service Sysmon64, winlogbeat status
   - 5 dòng cuối winlogbeat log
   - .\winlogbeat.exe version

AN TOÀN:
- KHÔNG tắt Windows Defender ở Pha 2 — chỉ tắt khi Pha 4 (Atomic Red Team).
- KHÔNG chạy payload tấn công ở bước này.
- Nếu Defender chặn tải Sysmon → thêm exclusion cho C:\Sysmon, không tắt toàn bộ AV.
````

### 5.3 Sysmon — chi tiết bước cài

**URL chính thức:**

- Sysmon zip: `https://download.sysinternals.com/files/Sysmon.zip`
- SwiftOnSecurity config: `https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml`

**Lệnh trong PowerShell as Administrator:**

```powershell
# Tải Sysmon
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip `
                  -OutFile C:\Sysmon.zip
Expand-Archive -Path C:\Sysmon.zip -DestinationPath C:\Sysmon -Force
Remove-Item C:\Sysmon.zip

# Tải SwiftOnSecurity config vào cùng folder
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml `
                  -OutFile C:\Sysmon\sysmonconfig-export.xml

# Cài Sysmon (yêu cầu Administrator)
cd C:\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
# → "Sysmon installed."
```

**Verify Sysmon hoạt động:**

```powershell
# Service status
Get-Service Sysmon64
# Status   : Running
# StartType: Automatic

# Event đang sinh ra
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5 |
  Format-List TimeCreated, Id, Message
# Phải thấy 5 event mới nhất, mỗi event có Id (1..29) tương ứng Sysmon event ID
```

### 5.4 Winlogbeat — chi tiết cài + `winlogbeat.yml`

**URL:**

```
https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.19.0-windows-x86_64.zip
```

**Cài (PowerShell as Administrator):**

```powershell
# Tải
Invoke-WebRequest -Uri https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.19.0-windows-x86_64.zip `
                  -OutFile C:\winlogbeat.zip
Expand-Archive -Path C:\winlogbeat.zip -DestinationPath 'C:\Program Files\' -Force
Rename-Item 'C:\Program Files\winlogbeat-8.19.0-windows-x86_64' 'C:\Program Files\Winlogbeat'
Remove-Item C:\winlogbeat.zip
```

**File `C:\Program Files\Winlogbeat\winlogbeat.yml` đầy đủ** (backup file gốc thành `.bak` trước):

```yaml
# === VN-SOC Lab — winlogbeat.yml ===
# Thay <HOSTNAME> bằng $env:COMPUTERNAME thực tế trước khi save

winlogbeat.event_logs:
  - name: Application
  - name: System
  - name: Security
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4103, 4104, 4105, 4106     # script block + module logging

# Output thẳng vào Logstash, KHÔNG dùng output.elasticsearch
output.logstash:
  hosts: ["43.228.215.234:5044"]
  # Beats input của lab chưa bật TLS — để mặc định, không cần ssl block

# Tags để Kibana lọc nhanh
tags: ["vn-soc-lab", "endpoint-win10", "<HOSTNAME>"]

# Logging Winlogbeat tự ghi
logging.level: info
logging.to_files: true
logging.files:
  path: C:\ProgramData\winlogbeat\Logs
  name: winlogbeat
  keepfiles: 7
  permissions: 0644

# ES self-monitoring tắt — lab dùng Logstash output, không tự gửi heartbeat sang ES
monitoring.enabled: false
```

**Test config + output:**

```powershell
cd "C:\Program Files\Winlogbeat"
.\winlogbeat.exe test config -e
# → Config OK

.\winlogbeat.exe test output -e
# → logstash: 43.228.215.234:5044... OK
```

Cả hai test PHẢI return OK mới sang bước register service.

**Register service + start:**

```powershell
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
Get-Service winlogbeat
# Status   : Running
# StartType: Automatic
```

### 5.5 Verify Pha 2 từ phía Win10

```powershell
# Service status
Get-Service Sysmon64, winlogbeat | Format-Table -AutoSize

# 5 event Sysmon mới nhất
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5 |
  Format-List TimeCreated, Id, Message

# Winlogbeat log — phải thấy connection established
Get-Content "C:\ProgramData\winlogbeat\Logs\winlogbeat" -Tail 30 |
  Select-String "Connection"
# Phải có dòng:
# "Connection to backoff(async(tcp://43.228.215.234:5044)) established"
```

### 5.6 Verify end-to-end từ phía VPS (Kali → SSH → server)

Phần này được Claude (Kali) verify sau khi Antigravity hoàn thành endpoint, đóng vòng *trust but verify* — không tin lời endpoint mà không kiểm chứng số liệu phía SIEM.

**Logstash pipeline counter:**

```bash
curl -s http://localhost:9600/_node/stats/events?pretty | grep -E '"(in|filtered|out)"'
# "in"       : 4493,
# "filtered" : 4493,
# "out"      : 4493,
```

→ 100% event đi qua pipeline được filter & output ra ES, không có event nào stuck.

**ES indices:**

```bash
PASSWORD=$(grep '^password' ~/elastic-credentials.txt | cut -d= -f2 | tr -d ' ')
curl -sk -u "elastic:$PASSWORD" "https://localhost:9200/_cat/indices/winlogbeat-*?v"
# health  status  index                  docs.count  store.size
# yellow  open    winlogbeat-2026.06.25       4417       5.5mb
```

→ Index thời gian được Logstash tự tạo theo pattern `winlogbeat-YYYY.MM.dd`. Chênh 76 doc so với Logstash counter là do ES default `refresh_interval=1s` + queue đang flush — **không phải data loss**.

**Sample document (Sysmon event_id=1 — process_creation, real):**

```yaml
_index           : winlogbeat-2026.06.25
@timestamp       : 2026-06-25T06:38:28.251Z
agent.type       : winlogbeat
agent.version    : 8.19.0
host.name        : DESKTOP-L7FCMBQ
host.hostname    : DESKTOP-L7FCMBQ

winlog.channel       : Microsoft-Windows-Sysmon/Operational
winlog.provider_name : Microsoft-Windows-Sysmon
winlog.event_id      : 1
winlog.computer_name : DESKTOP-L7FCMBQ
winlog.record_id     : 2679

# Sysmon event_data (raw — đường dẫn KQL chính)
winlog.event_data.Image            : C:\Windows\System32\rundll32.exe
winlog.event_data.OriginalFileName : RUNDLL32.EXE
winlog.event_data.CommandLine      : "C:\Windows\system32\rundll32.exe" /d acproxy.dll,PerformAutochkOperations
winlog.event_data.User             : NT AUTHORITY\SYSTEM
winlog.event_data.IntegrityLevel   : System
winlog.event_data.ParentImage      : C:\Windows\System32\svchost.exe
winlog.event_data.ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
winlog.event_data.ParentProcessId  : 1180
winlog.event_data.ProcessId        : 3008
winlog.event_data.Hashes           : MD5=EF3179D498793BF4234F708D3BE28633,SHA256=B53F3C0CD32D7F20849850768DA6431E5F876B...

# ECS normalized (Winlogbeat processor + Logstash pipeline)
event.kind     : event
event.code     : 1
event.category : sysmon
event.action   : Process Create (rule: ProcessCreate)
event.provider : ['Microsoft-Windows-Sysmon', 'Microsoft-Windows-Sysmon']

tags : [vn-soc-lab, endpoint-win10, DESKTOP-L7FCMBQ,
        beats_input_codec_plain_applied, sysmon]
ecs.version : 8.0.0
```

**Các điểm verify được:**

| # | Kỳ vọng | Thực tế | OK? |
|---|---|---|---|
| 1 | Pipeline gắn 3 tag `vn-soc-lab`, `endpoint-win10`, `<HOSTNAME>` | tags chứa cả 3, hostname substitute thành `DESKTOP-L7FCMBQ` | ✅ |
| 2 | Branch filter Sysmon áp tag `sysmon` + `event.category=sysmon` | đúng cả 2 | ✅ |
| 3 | `agent.type == "winlogbeat"` (output vào nhánh winlogbeat) | đúng | ✅ |
| 4 | Index pattern `winlogbeat-YYYY.MM.dd` | `winlogbeat-2026.06.25` | ✅ |
| 5 | `event.provider` được set | `Microsoft-Windows-Sysmon` | ✅ |
| 6 | Sysmon raw fields trong `winlog.event_data.*` đầy đủ | Image, CommandLine, ParentImage, Hashes, User... | ✅ |

### 5.6.1 Audit Sysmon — breakdown event_id

Aggregation `winlog.channel = "Microsoft-Windows-Sysmon/Operational"` trên 2675 Sysmon docs:

| Count | event_id | Loại | MITRE liên quan |
|---:|---:|---|---|
| 2038 | 13 | Registry value set | T1547.001 Run keys, T1112 modify registry |
| 276 | 11 | File create | T1105 ingress tool transfer, T1027 drop |
| 275 | 1 | Process creation | T1059 (PowerShell/CMD execution) |
| 60 | 22 | DNS query | T1071.004 / T1568.002 C2 |
| 25 | 3 | Network connection | T1071.001 web protocol |
| 3 | 5 | Process terminated | (signal, không có MITRE trực tiếp) |
| 1 | 16 | Sysmon config changed | (self-monitoring) |
| 1 | 4 | Sysmon state changed | (self-monitoring) |

→ Đủ data type cho **R1, R3, R5** trong Pha 3 ngay lập tức. **R2** (LSASS access — Sysmon event_id 10) hiện 0 hit vì SwiftOnSecurity chỉ log khi truy cập đáng ngờ; cần Pha 4 chạy Atomic T1003 để sinh. **R4** (brute-force) dùng Security channel chứ không Sysmon — vẫn khả thi vì Winlogbeat đang thu Security channel.

### 5.6.2 Phát hiện kỹ thuật cần biết khi viết KQL (Pha 3)

**Vấn đề 1 — `event.action` không khớp pipeline `translate` thiết kế.**

Pipeline thiết kế ghi `event.action = "process_creation"` (snake_case). Thực tế trong ES:

```
event.action = "Process Create (rule: ProcessCreate)"
```

Nguyên nhân: Winlogbeat 8.x có built-in processor đọc trường `RuleName` của Sysmon, set `event.action` **trước khi** event đi qua Logstash. Filter `translate` của mình mặc định `override => false` nên không ghi đè field đã tồn tại.

→ **Không phải bug, là design difference.** Winlogbeat-native gán cụ thể hơn (kèm rule name) → giữ nguyên cho Pha 3, viết KQL dùng `winlog.event_id` (hoặc `event.code`) thay vì phụ thuộc `event.action` text.

**Vấn đề 2 — `winlog.event_id` là kiểu `text`, không phải `keyword`.**

ES trả lỗi khi aggregate trực tiếp:

```
illegal_argument_exception: Fielddata is disabled on [winlog.event_id]
Please use a keyword field instead.
```

Phải dùng `winlog.event_id.keyword` cho mọi aggregation / sort / threshold rule. Hoặc dùng `event.code` (đã ECS-mapped, type keyword sẵn) — đây là cách khuyến nghị.

→ **Khắc phục dài hạn (đề xuất Pha 3+):** chạy `winlogbeat setup --index-management` từ endpoint thẳng vào ES để cài Winlogbeat index template chuẩn ECS. Cho lab hiện tại chấp nhận dùng `.keyword` suffix hoặc `event.code`.

**KQL pattern an toàn cho Pha 3:**

```
# An toàn (Recommended):
event.code: "1" AND winlog.provider_name: "Microsoft-Windows-Sysmon"

# Cũng OK:
winlog.event_id: "1" AND winlog.provider_name: "Microsoft-Windows-Sysmon"

# Tránh — phụ thuộc text Winlogbeat parse (có thể đổi theo version):
event.action: "Process Create (rule: ProcessCreate)"
```

### 5.7 Trạng thái cuối Pha 2

| Hạng mục | Kết quả |
|---|---|
| Sysmon v15 (SwiftOnSecurity) cài trên endpoint | ✅ |
| Winlogbeat 8.19.0 service Running, StartType Automatic | ✅ |
| TCP Lumberjack Win10 → Logstash:5044 established | ✅ |
| Logstash filter chain hoạt động (events.in == events.out) | ✅ 4493 events |
| ES nhận và index hoá tài liệu | ✅ 4417 docs |
| Sysmon event đầy đủ 5 loại quan trọng (e1/3/11/13/22) | ✅ |
| Tags `vn-soc-lab` truyền end-to-end vào ES | ✅ |
| Pipeline normalize ECS field `event.*` | ✅ |
| Sẵn sàng tạo detection rule trong Kibana | ✅ Pha 3 |

---

## 6. Pha 3-9 — Tổng quan các pha mở rộng

> Mỗi pha có file `pha{N}-results.md` riêng — chi tiết stage-by-stage, lessons learned, smoke-test output. Section này tổng hợp executive view + key takeaways cho recruiter.

### 6.1 Pha 3 — Detection Engineering (R1-R5) — `pha3-results` trong [`detection-rules/`](detection-rules/)

| Rule | MITRE | Spec | Smoke-test |
|---|---|---|---|
| R1 PowerShell Encoded Command | T1059.001 | [link](detection-rules/R1-T1059.001-powershell-encoded.md) | 5+1 alerts |
| R2 LSASS Memory Access | T1003.001 | [link](detection-rules/R2-T1003.001-lsass-access.md) | 1 alert (Defender FP) |
| R3 Registry Run Key | T1547.001 | [link](detection-rules/R3-T1547.001-registry-run-key.md) | 4 alerts |
| R4 Brute Force Logon | T1110 | [link](detection-rules/R4-T1110-brute-force-login.md) | 1 alert (sau fix threshold) |
| R5 Non-Browser Outbound HTTP/HTTPS | T1071.001 | [link](detection-rules/R5-T1071.001-non-browser-outbound.md) | 55 → 0 sau tune |

8 lesson về KQL pitfalls — xem [`detection-rules/README.md §Pitfalls`](detection-rules/README.md).

### 6.2 Pha 4 — Adversary Emulation — [`pha4-results.md`](pha4-results.md)

Atomic Red Team chain: **T1547.001 → T1059.001 → T1110** trong 18 phút.
- Tools: invoke-atomicredteam, Sysmon, kill-chain narrative.
- 5 lessons mới: time-window verify trap, Sysmon ProcessAccess rule, Defender behavior killing chain, FP tuning R5 (-100% noise), reproducibility sweep.

### 6.3 Pha 5 — Incident Response — [`incidents/VN-SOC-2026-0001-killchain.md`](incidents/VN-SOC-2026-0001-killchain.md)

NIST 800-61 incident report:
- Investigator narrative dạng story (không phải log dump).
- ProcessGuid pivot cho parent-child chain.
- IoC extracted (hash, regkey, IP).
- MITRE kill-chain mapped 3 tactics.

### 6.4 Pha 6 — Network Detection Layer (R6-R8) — [`pha6-results.md`](pha6-results.md)

+1 SOC-Tools VM (Ubuntu 22.04, 3 GB→4 GB tại Pha 9, 23 GB disk).
- Suricata 8.0.5 native trên `ens33` + ET Open ruleset.
- DVWA Docker (port 8080) + Filebeat 2 input multi-source.
- Logstash main.conf refactor: 3-branch routing (winlogbeat/suricata/dvwa-apache).
- 8 lessons: LVM extend, pipe broken `curl|sudo`, ECS v8 grok rename, KQL `.keyword` pitfalls 5 bugs.

### 6.5 Pha 7 — Wazuh HIDS Full Stack — [`pha7-results.md`](pha7-results.md)

+1 SOC-Wazuh VM (Ubuntu 22.04, 4 GB RAM, 50 GB disk).
- Wazuh 4.9.2 Manager + Indexer + Dashboard (clone wazuh-docker single-node, heap tune `-Xms1g`).
- Win10 Wazuh Agent MSI install → 2 agents active.
- Multi-SIEM coexistence: Elastic (primary) + Wazuh (HIDS-focused). Win10 dual-ship Winlogbeat→Elastic + Wazuh Agent→Manager.
- 5 lessons: RAM minimum 4 GB (không 2), non-LVM resize đơn giản, disk 14 GB Wazuh baseline, MSI auto-enrollment race → duplicate name, Python f-string quirk.

### 6.6 Pha 8 — AI/ML Detection (R9) — [`pha8-results.md`](pha8-results.md)

ML enrichment inline trên Logstash dvwa-apache branch.
- Dataset: 459 URL synthesize (sqli/xss/lfi/probe vs benign).
- Model: TF-IDF `char_wb` (2,5) + LogisticRegression class_weight=balanced.
- Serving: Flask + gunicorn Docker multi-stage (Python 3.12-slim), mem_limit 400 MB.
- Logstash filter-http call `127.0.0.1:5000/predict` → gắn `[ml]` object vào event.
- **R9 fired 9 alerts 100% TP** (sqli/lfi/xss/.env/.git/wp-config) tại threshold 0.7.
- 5 lessons: NumPy x86-64-v2 baseline (QEMU CPU không support), Python 3.13 wheel availability, pickle compat across sklearn version, synthetic dataset over-optimism, Logstash interpolation `%{}` syntax.

### 6.7 Pha 9 — SOAR & Case Management — [`pha9-results.md`](pha9-results.md)

Auto-pipeline: detection alert → ES → bridge → n8n → TheHive case.
- TheHive 5.4 stack (Cassandra 4 + ES 7) trên SOC-Tools (sau RAM upgrade 2→4 GB).
- n8n 1.74.1 `network_mode: host` trên VPS.
- SSH reverse tunnel `autossh -R 0.0.0.0:9000:SOC-Tools:9000` (cross-network bridge VPS↔SOC-Tools).
- systemd timer (30s) poll ES alerts → POST n8n webhook (workaround vì Kibana Basic license không có `.webhook` connector).
- Smoke-test: **34 cases tổng cộng** (3 manual + 31 auto-forwarded từ R6/R7/R8/R9).
- 7 lessons: n8n auth env deprecation, TheHive 5 args khác v4, perms cần org-admin/analyst, SSH GatewayPorts + Docker `network_mode: host`, n8n HTTP node default GET, Kibana license tier, f-string quirk repeat.

### 6.7b Pha 9.5 — Cortex Analyzer Integration — [`pha9.5-results.md`](pha9.5-results.md)

Khâu cuối khép SOAR loop: TheHive observables auto-enrich via Cortex analyzers.
- Cortex 3.1.7 + ES 7 standalone trên SOC-Wazuh (tận dụng RAM headroom 1.5 GB, cùng LAN 192.168.154.x với SOC-Tools — không cần tunnel).
- 2 analyzers free-tier: VirusTotal_GetReport (500/day) + AbuseIPDB (1000/day).
- TheHive 5 wire qua `--cortex-hostnames/port/proto/keys` command args (no runtime config endpoint).
- Smoke-test: observable `185.220.101.1` (Tor exit) → AbuseIPDB → report attach (abuse score 100, hostname `berlin01.tor-exit.artikel10.org`, 56 reports) vào case #40.
- 5 lessons: ES mem_limit 600m→900m (thrashing), job_directory bind mount (not named volume), Cortex 3 CSRF strict (GUI bootstrap), TheHive 5 Cortex config via container args only, v0 `/api/case/.../artifact` fallback khi v1 báo 403.

### 6.8 Toàn cảnh — Detection rules R1-R9 cover 9 MITRE techniques

| Tactic (TA) | Technique | Rule | Source |
|---|---|---|---|
| Reconnaissance (TA0043) | T1595 Active Scanning | R6 | Suricata |
| Reconnaissance (TA0043) | T1595.002 Vulnerability Scanning UA | R7 | DVWA Apache log |
| Initial Access (TA0001) | T1190 Exploit Public-Facing Application | R9 | DVWA + ML score |
| Execution (TA0002) | T1059.001 PowerShell | R1 | Sysmon |
| Persistence (TA0003) | T1547.001 Registry Run Key | R3 | Sysmon |
| Credential Access (TA0006) | T1003.001 LSASS Memory Access | R2 | Sysmon |
| Credential Access (TA0006) | T1110 Brute Force | R4 | Security event 4625 |
| Discovery (TA0007) | T1083 File and Directory Discovery | R8 | DVWA Apache log |
| Command & Control (TA0011) | T1071.001 Web Protocols | R5 | Sysmon network |

### 6.9 Lessons learned aggregate (Pha 3-9)

Tổng cộng **~40 lessons learned** trong các pha mở rộng — gold cho phỏng vấn. Highlights:

| # | Lesson | Pha | Take-away |
|---|---|---|---|
| L1 | KQL `.keyword` cho aggregation; quote = literal; `/*` Lucene comment | 3 / 6 | Always test KQL trên Discover trước khi gắn rule. |
| L2 | Atomic Red Team time-window trap — alert có thể ngoài window do shipping delay | 4 | Mở rộng range hoặc query no-time-filter. |
| L3 | Sysmon config XML must include ProcessAccess RuleGroup cho R2 fire | 4 | Validate config bằng `Sysmon64 -c file.xml`. |
| L4 | False-positive tuning > rule deletion — R5 exclude Antigravity `agy.exe` | 4 | Doc whitelist + maintain in rule code. |
| L5 | Logstash ECS v8 auto-rename grok fields (clientip→source.address) | 6 | Check `dvwa-apache-*` mapping sau pipeline change. |
| L6 | Wazuh RAM minimum thực tế 4 GB cho full stack | 7 | Docs "minimal 2 GB" chỉ đúng cho Manager-only. |
| L7 | MSI race condition → duplicate agent name → restart service force reload key | 7 | Always force `agent-auth.exe` + restart, không dựa auto-enrollment. |
| L8 | NumPy 2.x wheel cần x86-64-v2; pin `numpy==1.26.4` cho QEMU CPU older | 8 | Verify VPS CPU flags trước khi pick stack. |
| L9 | Synthetic dataset 1.0 AUC misleading — augment với real Apache log | 8 | Raise threshold tạm thời (0.5→0.7) trong khi retrain. |
| L10 | Kibana Basic license không có `.webhook` connector → systemd timer workaround | 9 | Free-tier SOAR pattern cho lab/SME. |
| L11 | SSH `-R` default bind 127.0.0.1 — cần GatewayPorts yes + bind `0.0.0.0` + container `network_mode: host` | 9 | 3 layer config phải đúng đồng thời. |
| L12 | n8n HTTP Request typeVersion 4.2 default Method=GET — explicit set POST | 9 | TheHive trả 404 cho GET → misleading. |

Toàn bộ lessons xem chi tiết trong file `pha{N}-results.md` tương ứng + `detection-rules/README.md`.

### 6.10 File mới Pha 3-9 (high-level)

```
detection-rules/         R1-R9.md + R*.ndjson + README convention
incidents/               VN-SOC-2026-0001-killchain.md (NIST 800-61)
configs/                 main.conf (multi-branch Logstash) + filebeat-soc-tools.yml
                         docker-compose-dvwa.yml + wazuh-docker-compose.yml
ml-detection/api/        Dockerfile multi-stage + app.py + train/ scripts
soar/n8n/                docker-compose.yml + workflow JSON
soar/thehive/            docker-compose.yml (Cassandra 4 + ES 7 + TheHive 5)
soar/bridge/             alert-forwarder.py + systemd service+timer
pha3-results … pha9-results.md  (5 doc files, ~2500 lines total)
```

---

## 7. Sự cố & xử lý đã ghi nhận

Phần này quan trọng cho recruiter — chứng minh năng lực debug, không phải "copy lệnh từ tutorial".

### 7.1 `debconf: unable to initialize frontend: Dialog/Readline` khi apt install qua SSH

**Triệu chứng:** Lúc `apt install elasticsearch`, debconf bung warning frontend.
**Nguyên nhân:** SSH không cấp pseudo-TTY → debconf fall back qua Teletype.
**Xử lý:** Đặt `DEBIAN_FRONTEND=noninteractive` cho các install sau (Kibana, Logstash). Không phải lỗi.

### 7.2 Auto-generated `elastic` password trôi qua scrollback

**Triệu chứng:** Output cài Elastic in password chỉ một lần lúc post-install, không kịp capture.
**Xử lý:** Re-issue bằng tool chính thức: `elasticsearch-reset-password -u elastic -b -s`. Redirect vào file chmod 600. Đây là path chính thức của Elastic — không phải workaround.

### 7.3 Logstash log INFO `Not eligible for data streams`

**Triệu chứng:** Sau restart, log Logstash xuất hiện:
```
Not eligible for data streams because config contains one or more settings
that are not compatible with data streams: {"index"=>"winlogbeat-%{+YYYY.MM.dd}"}
```
**Nguyên nhân:** Chỉ định `index =>` rõ ràng → Logstash buộc dùng time-based index thay vì data stream.
**Xử lý:** Đây là hành vi **mong muốn** — pattern `winlogbeat-*` đúng theo yêu cầu báo cáo. Không cần fix.

### 7.4 Logstash WARN `ssl_verification_mode disabled`

**Triệu chứng:** Log Logstash:
```
You have enabled encryption but DISABLED certificate verification,
to make sure your data is secure set `ssl_verification_mode => full`
```
**Nguyên nhân:** Cert ES là self-signed; lab chấp nhận `ssl_verification_mode => none`.
**Khuyến nghị production:** Mount `/etc/elasticsearch/certs/http_ca.crt` vào Logstash, đổi `ssl_verification_mode => full` + `ssl_certificate_authorities`. Chưa làm trong lab.

### 7.5 ⚠️ UFW chặn 5601 nhưng `curl` trên server vẫn HTTP 200

**Triệu chứng:** Test `curl http://43.228.215.234:5601/api/status` trên chính VPS trả 200 mặc dù UFW chưa mở 5601.
**Nguyên nhân:** Request loopback từ server tự gọi public IP của mình → traffic đi qua interface `lo`, **không** qua INPUT chain → UFW không thấy.
**Bài học:** *Test bảo mật firewall phải test từ MÁY KHÁC.* Đã chạy lại từ Kali → ban đầu 5601 timeout. Sau `ufw allow 5601` mới phản hồi 200.
**Ý nghĩa:** Chính xác là kiểu lỗi "tưởng đã pass test nhưng không". Lab dạy phải nghi ngờ chính kết quả test của mình.

### 7.6 Pending kernel upgrade trên Ubuntu 24.04

**Triệu chứng:** `needrestart` báo kernel running ≠ kernel installed (`6.8.0-54` vs `6.8.0-124`).
**Quyết định:** **Không** reboot trong quá trình setup — rớt SSH + service. Tất cả service đã `enable`, sau reboot tự lên. Reboot là quyết định ops, không phải side-effect apt.

### 7.7 Kibana báo "Detection Engine permissions required" — thực ra thiếu encryption keys

**Triệu chứng:** Mở Kibana → Security → Rules → Detection rules, nhận:
```
Detection engine permissions required
You do not have the required permissions for viewing the detection engine.
For more help, contact your administrator.
```
User đăng nhập đang là `elastic` (superuser, đáng lẽ có mọi quyền).

**Diagnosis (không tin UI message):** Đọc Kibana log:

```bash
sudo tail -200 /var/log/kibana/kibana.log | grep -iE "(detection|alert|encrypt)"
```

Thấy:
```
ERROR  plugins.streams
Unable to create alerts client because the Encrypted Saved Objects plugin
is missing encryption key. Please set xpack.encryptedSavedObjects.encryptionKey
in the kibana.yml or use the bin/kibana-encryption-keys command.
```

**Nguyên nhân:** `kibana-setup --enrollment-token` (§4.6) KHÔNG tự sinh 3 encryption key cần cho Detection Engine, Alerts, Fleet. Kibana UI hiện message "permission required" gây hiểu lầm là RBAC issue, thực ra là **alerts client không init được**.

**Xử lý** (xem §4.7 — đã đưa vào Pha 1 ngay từ đầu để người reproduce không stuck):

```bash
KEY_SAVED=$(openssl rand -hex 32)
KEY_REPORTING=$(openssl rand -hex 32)
KEY_SECURITY=$(openssl rand -hex 32)

printf '%s' "$KEY_SAVED"     | sudo /usr/share/kibana/bin/kibana-keystore add --stdin xpack.encryptedSavedObjects.encryptionKey
printf '%s' "$KEY_REPORTING" | sudo /usr/share/kibana/bin/kibana-keystore add --stdin xpack.reporting.encryptionKey
printf '%s' "$KEY_SECURITY"  | sudo /usr/share/kibana/bin/kibana-keystore add --stdin xpack.security.encryptionKey

sudo systemctl restart kibana

# Đợi ready, refresh tab Kibana (hard reload Ctrl+Shift+R)
```

**Bài học:**
1. KHÔNG tin error message của UI — đọc service log để diagnose.
2. Kibana 8.x `kibana-setup` flow **chưa đủ** cho Detection Engine — phải thêm encryption keys manual.
3. Đây là lỗi *non-obvious* — recruiter sẽ ấn tượng nếu thấy bạn biết debug bằng log thay vì Google ngay.

---

## 8. Hardening đã áp dụng vs còn thiếu

| # | Hardening | Trạng thái | Cách làm trong production |
|---|---|---|---|
| 1 | X-Pack Security ON (TLS internal) | ✅ Default 8.x | Same — đã đúng |
| 2 | UFW default deny + explicit allow | ✅ | Same + `from <VPN_CIDR>` để giới hạn nguồn |
| 3 | ES không expose `:9200` ra Internet | ✅ | Same + SSH tunnel cho admin |
| 4 | Credentials chmod 600 | ✅ | Thay bằng Vault / SOPS / sealed-secrets |
| 5 | Kibana encryption keys (keystore) | ✅ | Same — backup `kibana.keystore` file |
| 6 | Heap 512 MB | ✅ lab | Production: 50% RAM cap 30 GB, `bootstrap.memory_lock: true` |
| 7 | `bootstrap.memory_lock: true` | ❌ Chưa | + `LimitMEMLOCK=infinity` trong systemd unit |
| 8 | Kibana TLS (HTTPS frontend) | ❌ HTTP plain trên 5601 | Reverse proxy nginx/Caddy + Let's Encrypt; hoặc `server.ssl.*` |
| 9 | Beats input TLS (Logstash:5044) | ❌ Plain TCP | `ssl => true` ở Logstash input + ship client cert |
| 10 | Logstash verify ES cert chain | ❌ `ssl_verification_mode: none` | Distribute `http_ca.crt`, `verification_mode: full` |
| 11 | RBAC + Spaces trong Kibana | ❌ Chỉ `elastic` superuser | Role `soc-analyst-readonly`, space per team |
| 12 | ILM policy index lifecycle | ❌ Index không tự xoá | Hot → warm → cold; delete sau 30 ngày |
| 13 | Audit log Elasticsearch | ❌ | `xpack.security.audit.enabled: true` |

Phần "còn thiếu" sẽ đề cập trong `roadmap.md §G` (mở rộng nếu còn thời gian).

---

## 9. Kỹ năng đã chứng minh tới hiện tại

| Domain | Kỹ năng | Bằng chứng |
|---|---|---|
| Linux SysAdmin | systemd, journal, apt signed-by, UFW, SSH key, sysctl | §4.2, §4.3, §4.10 |
| JVM tuning | Heap min/max via `jvm.options.d/`, verify on process args | §4.4 |
| TLS & PKI | Self-signed CA, enrollment flow, keystore vs yml plain | §4.5, §4.7 |
| Logstash DSL | input/filter/output, translate plugin, ECS v8 schema, conditional branch | `configs/winlogbeat.conf` + §4.9 |
| Windows endpoint telemetry | Sysmon config XML, Winlogbeat channels, PowerShell logging event ID | §5 |
| ECS schema | Phân biệt `winlog.event_data.*` raw vs `event.*` ECS-mapped | §5.6 sample doc |
| Debugging | Đọc service log thay vì tin UI message (Kibana encryption keys issue) | §7.7 |
| Firewall testing | Hiểu loopback vs external interface trong UFW INPUT | §6.5 |
| Documentation | Cấu trúc 3 file report/roadmap/changelog, deploy-then-document protocol | repo này + `AGENTS.md` |
| Multi-agent collaboration | Claude Code (Kali) + Antigravity (Win10) cùng sửa 1 repo qua git | `AGENTS.md` §2 |
| AI tooling automation | SSH automation từ Claude, PowerShell automation từ Antigravity | toàn bộ Pha 1-2 |
| Endpoint detection design | Sysmon event_id breakdown, MITRE mapping, KQL safe pattern | §5.6.1 + §5.6.2 |
| Detection engineering | 5 KQL detection rules (custom query + threshold) mapping MITRE ATT&CK | `detection-rules/` |
| Adversary emulation | Atomic Red Team T1003.001 / T1547.001 / T1071.001 với cleanup safety + 5 lessons learned | `pha4-results.md` |
| Sysmon config tuning | Edit XML config thêm ProcessAccess RuleGroup, validate via `-c` | `pha4-results.md §Lesson 1` |
| Incident response writeup | NIST 800-61 format Incident Report với KQL pivot + IoC extract + kill-chain narrative | `incidents/VN-SOC-2026-0001-killchain.md` |
| MITRE ATT&CK kill-chain mapping | 3 tactics chained (Persistence T1547 / Execution T1059 / Credential Access T1110) trong 18 phút | `incidents/VN-SOC-2026-0001 §2` |
| Log analysis pivot | ProcessGuid pivot, parent-child process tree, KQL multi-field correlation | `incidents/VN-SOC-2026-0001 §3 + §8.A` |
| False-positive tuning | R5 exclude `agy.exe` (Antigravity) — FP reduced 100% | `pha4-results.md §Lesson 4` |
| Network IDS deployment | Suricata 8.0.5 native interface monitor + ET Open ruleset 50k sigs | `pha6-results.md` |
| Multi-source Logstash pipeline | 3-branch routing winlogbeat/suricata/dvwa-apache + grok COMBINEDAPACHELOG | `configs/main.conf` |
| Docker production-like deployment | DVWA, Wazuh full stack, TheHive 5 stack, ml-url-api multi-stage, n8n host network | `configs/*.yml` + `soar/` + `ml-detection/` |
| HIDS architecture | Wazuh Manager + Indexer (OpenSearch fork) + Dashboard, agent enrollment, multi-SIEM dual-ship | `pha7-results.md` |
| OpenSearch tuning | Heap min/max, `vm.max_map_count`, cluster health on disk-constrained VM | `pha7-results.md §3.5` |
| ML inline serving | TF-IDF char n-gram + LogReg, Flask + gunicorn Docker, Logstash filter-http enrichment | `pha8-results.md` + `ml-detection/api/` |
| ML cross-version compat | Pin sklearn + numpy đồng nhất train + serve qua multi-stage Docker build | `pha8-results.md §Lessons 1-3` |
| SOAR & case management | TheHive 5 stack + n8n workflow automation + ES alerts bridge → 34 cases auto | `pha9-results.md` + `soar/` |
| Cross-network SSH tunneling | autossh reverse `-R 0.0.0.0:9000` + GatewayPorts + container `network_mode: host` | `pha9-results.md §3.5 + §3.6` |
| Free-tier license workaround | systemd timer poll ES alerts → n8n webhook (Kibana Basic không có `.webhook`) | `soar/bridge/alert-forwarder.py` |
| API-driven config | Kibana Detection Engine REST API tạo R9, TheHive REST API auth + org/user/key bootstrap | `pha8-results.md §3.8` + `pha9-results.md §3.4` |
| Threat-intel auto-enrich | Cortex 3 + VirusTotal + AbuseIPDB → TheHive observables auto-enrich (case #40 Tor IP abuse 100) | `pha9.5-results.md` |
| Docker socket sibling spawn | Cortex spawn analyzer container via host docker socket — job_directory bind mount (KHÔNG named volume) | `pha9.5-results.md §Lesson 2` |

---

## 10. Phụ lục — lệnh tham khảo

### 10.1 One-shot reproduce Pha 1 (script bash)

```bash
#!/usr/bin/env bash
# === VN-SOC Lab — Pha 1 bare-metal deploy ===
set -euo pipefail

# [0] Pre-check
sysctl vm.max_map_count    # phải ≥ 262144
df -h /                    # free disk ≥ 20 GB

# [1] Pre-req + Elastic repo
sudo apt-get update -qq
sudo apt-get install -y -qq apt-transport-https wget gnupg curl ca-certificates openssl
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] \
https://artifacts.elastic.co/packages/8.x/apt stable main' \
  | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt-get update -qq

# [2] Elasticsearch + heap 512MB
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y elasticsearch
sudo tee /etc/elasticsearch/jvm.options.d/heap.options <<<'-Xms512m
-Xmx512m'
sudo systemctl daemon-reload && sudo systemctl enable --now elasticsearch

# [3] Reset & lưu password
ELASTIC_PW=$(sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -b -s)
umask 077
printf '[elastic]\nusername=elastic\npassword=%s\nURL=https://%s:9200\n' \
  "$ELASTIC_PW" "$(hostname -I | awk '{print $1}')" > ~/elastic-credentials.txt

# [4] Kibana + enrollment + bind public
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y kibana
TOKEN=$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)
sudo /usr/share/kibana/bin/kibana-setup --enrollment-token "$TOKEN"
sudo bash -c '
  if grep -q "^server.host:" /etc/kibana/kibana.yml; then
    sed -i "s|^server.host:.*|server.host: \"0.0.0.0\"|" /etc/kibana/kibana.yml
  else
    echo "server.host: \"0.0.0.0\"" >> /etc/kibana/kibana.yml
  fi'

# [5] Kibana encryption keys (cho Detection Engine)
KEY_SAVED=$(openssl rand -hex 32)
KEY_REPORTING=$(openssl rand -hex 32)
KEY_SECURITY=$(openssl rand -hex 32)
printf '%s' "$KEY_SAVED"     | sudo /usr/share/kibana/bin/kibana-keystore add --stdin xpack.encryptedSavedObjects.encryptionKey
printf '%s' "$KEY_REPORTING" | sudo /usr/share/kibana/bin/kibana-keystore add --stdin xpack.reporting.encryptionKey
printf '%s' "$KEY_SECURITY"  | sudo /usr/share/kibana/bin/kibana-keystore add --stdin xpack.security.encryptionKey
sudo systemctl enable --now kibana

# [6] Logstash + pipeline (cần file configs/winlogbeat.conf trong repo)
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y logstash
sudo cp configs/winlogbeat.conf /etc/logstash/conf.d/winlogbeat.conf
sudo sed -i "s|<ELASTIC_PASSWORD>|$ELASTIC_PW|g" /etc/logstash/conf.d/winlogbeat.conf
sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t    # validate
sudo systemctl enable --now logstash

# [7] UFW
sudo ufw allow 22/tcp   comment "SSH"
sudo ufw allow 5044/tcp comment "Logstash Beats input"
sudo ufw allow 5601/tcp comment "Kibana UI"
sudo ufw reload

echo "✅ Pha 1 done"
echo "Kibana → http://$(hostname -I | awk '{print $1}'):5601"
echo "Password ở ~/elastic-credentials.txt"
```

### 10.2 Health-check vận hành

```bash
# Service status
for s in elasticsearch kibana logstash; do
  printf "%-15s active=%s enabled=%s\n" "$s" \
    "$(sudo systemctl is-active $s)" \
    "$(sudo systemctl is-enabled $s)"
done

# Port listening
sudo ss -tlnp | grep -E ':(5044|5601|9200|9300|9600)'

# Pipeline events counter
curl -s http://localhost:9600/_node/stats/events?pretty | grep -E '"(in|filtered|out)"'

# ES health
PASSWORD=$(grep '^password' ~/elastic-credentials.txt | cut -d= -f2 | tr -d ' ')
curl -sk -u "elastic:$PASSWORD" https://localhost:9200/_cluster/health?pretty

# Index winlogbeat-*
curl -sk -u "elastic:$PASSWORD" "https://localhost:9200/_cat/indices/winlogbeat-*?v"

# Sample document mới nhất (Sysmon)
curl -sk -u "elastic:$PASSWORD" \
  "https://localhost:9200/winlogbeat-*/_search?size=1&sort=@timestamp:desc&pretty"

# Kibana keystore (chỉ list tên, không show value)
sudo /usr/share/kibana/bin/kibana-keystore list

# Tail log
sudo tail -50 /var/log/elasticsearch/elasticsearch.log
sudo tail -50 /var/log/kibana/kibana.log
sudo tail -50 /var/log/logstash/logstash-plain.log
```

### 10.3 Debug từ phía Windows endpoint

```powershell
# Service status
Get-Service Sysmon64, winlogbeat | Format-Table -AutoSize

# Event Sysmon mới nhất
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5 |
  Format-List TimeCreated, Id, Message

# Test ship output (kiểm tra Logstash:5044 reachable)
cd "C:\Program Files\Winlogbeat"
.\winlogbeat.exe test output -e

# Winlogbeat log
Get-Content "C:\ProgramData\winlogbeat\Logs\winlogbeat" -Tail 30

# Restart winlogbeat service
Restart-Service winlogbeat
```

---

## 11. File Inventory

Tất cả file đã sửa/tạo trong dự án — checklist khi reproduce.

### 11.1 Trên VPS `43.228.215.234`

| Path | Loại | Vai trò |
|---|---|---|
| `/etc/apt/sources.list.d/elastic-8.x.list` | tạo mới | Elastic 8.x APT repo |
| `/usr/share/keyrings/elasticsearch-keyring.gpg` | tạo mới | GPG signing key (binary) |
| `/etc/elasticsearch/elasticsearch.yml` | auto-gen | Mặc định 8.x — không sửa |
| `/etc/elasticsearch/jvm.options.d/heap.options` | tạo mới | Override heap = 512MB |
| `/etc/elasticsearch/certs/` | auto-gen | Self-signed http.p12 + transport.p12 |
| `/etc/kibana/kibana.yml` | sửa | Set `server.host: "0.0.0.0"` + enrollment auto-write `elasticsearch.hosts`, CA fingerprint |
| `/etc/kibana/kibana.keystore` | sửa | 3 encryption keys (encrypted at rest) |
| `/etc/logstash/conf.d/main.conf` | tạo mới (Pha 6 rename from winlogbeat.conf) | Pipeline VN-SOC multi-branch + ML enrichment Pha 8 — bản local: [`configs/main.conf`](configs/main.conf) |
| `~/elastic-credentials.txt` | tạo mới | chmod 600 — password elastic user |
| `/var/log/elasticsearch/elasticsearch.log` | auto-gen | Service log |
| `/var/log/kibana/kibana.log` | auto-gen | Service log |
| `/var/log/logstash/logstash-plain.log` | auto-gen | Service log |
| UFW rules | sửa | `allow 22, 5044, 5601` |
| `~/ml-detection/api/` (Pha 8) | tạo mới | Flask URL classifier Docker stack |
| Container `ml-url-api` (Pha 8) | docker run | Loopback :5000, mem_limit 400 MB |
| `~/soar/n8n/` (Pha 9) | tạo mới | n8n compose (host network) |
| Container `n8n` (Pha 9) | docker run | n8n 1.74.1, :5678 loopback |
| `/opt/vnsoc-soar/alert-forwarder.py` (Pha 9) | tạo mới | ES poll → n8n bridge |
| `/etc/systemd/system/vnsoc-soar.service` + `.timer` (Pha 9) | tạo mới | Run every 30s |
| `/etc/vnsoc-soar.env` (Pha 9) | tạo mới | chmod 640 — ES_PASS + N8N webhook |
| `/var/lib/vnsoc-soar/state.json` (Pha 9) | runtime | Last-seen alert timestamp |
| `/etc/ssh/sshd_config` (Pha 9) | sửa | `GatewayPorts yes` cho reverse tunnel cross-Docker |

### 11.2 Trên SOC-Tools VM `192.168.154.165` (Pha 6 + 9)

| Path | Loại | Vai trò |
|---|---|---|
| Suricata 8.0.5 native | install | NIDS monitor `ens33` (Pha 6) |
| ET Open ruleset | install | 50k+ signatures (Pha 6) |
| `~/dvwa/docker-compose.yml` | tạo mới | DVWA target Pha 6 |
| Container `vnsoc-dvwa` | docker run | DVWA :8080 |
| `~/filebeat/filebeat.yml` | tạo mới | 2 input: suricata eve.json + apache access.log |
| `/etc/sysctl.d/99-thehive.conf` (Pha 9) | tạo mới | `vm.max_map_count=262144` |
| `~/soar/thehive/docker-compose.yml` (Pha 9) | tạo mới | Cassandra + ES 7 + TheHive 5 stack |
| Container `thehive-cassandra` | docker run | Cassandra 4.1.4, heap 512m |
| Container `thehive-elasticsearch` | docker run | ES 7.17.27, heap 512m |
| Container `thehive` | docker run | TheHive 5.4.0 :9000 |
| LVM extend operation | one-shot | `lvextend -l +100%FREE` (Pha 6) |
| RAM upgrade 2→4 GB (Pha 9) | VMware Settings | Required cho TheHive stack |

### 11.3 Trên SOC-Wazuh VM `192.168.154.163` (Pha 7)

| Path | Loại | Vai trò |
|---|---|---|
| `/etc/sysctl.d/99-wazuh.conf` | tạo mới | `vm.max_map_count=262144` |
| `~/soc-wazuh/wazuh-docker/single-node/` | git clone | Wazuh full stack template |
| `~/soc-wazuh/wazuh-docker/single-node/docker-compose.yml` | sửa | Patched heap `-Xms1g -Xmx1g`, snapshot trong [`configs/wazuh-docker-compose.yml`](configs/wazuh-docker-compose.yml) |
| `config/wazuh_indexer_ssl_certs/` | auto-gen | TLS certs (cá nhân) |
| Container `single-node-wazuh.manager-1` | docker run | Wazuh Manager :1514 / :1515 / :55000 |
| Container `single-node-wazuh.indexer-1` | docker run | OpenSearch :9200 |
| Container `single-node-wazuh.dashboard-1` | docker run | Wazuh Dashboard :443 |
| Disk expand 20→50 GB (Pha 7) | VMware Settings + `growpart` + `resize2fs` | Stack ăn 14 GB baseline |

### 11.4 Trên Endpoint Win10 `DESKTOP-L7FCMBQ`

| Path | Loại | Vai trò |
|---|---|---|
| `C:\Sysmon\Sysmon64.exe` | tải về | Sysmon binary |
| `C:\Sysmon\sysmonconfig-export.xml` | tải về | SwiftOnSecurity config |
| `C:\Program Files\Winlogbeat\` | tải về | Winlogbeat installation folder |
| `C:\Program Files\Winlogbeat\winlogbeat.yml` | sửa | Cấu hình output.logstash + channels |
| `C:\Program Files\Winlogbeat\winlogbeat.yml.bak` | backup | Config gốc trước sửa |
| `C:\ProgramData\winlogbeat\Logs\winlogbeat` | auto-gen | Winlogbeat service log |
| Windows Service `Sysmon64` | install | Auto-start |
| Windows Service `winlogbeat` | install | Auto-start |
| `C:\Program Files (x86)\ossec-agent\` (Pha 7) | install | Wazuh Agent 4.9.2-1 MSI |
| `C:\Program Files (x86)\ossec-agent\ossec.conf` (Pha 7) | sửa | `<address>192.168.154.163</address>` |
| `C:\Program Files (x86)\ossec-agent\client.keys` (Pha 7) | auto-gen | Agent key sau enrollment |
| Windows Service `WazuhSvc` (Pha 7) | install | Auto-start |

### 11.5 Trên Workstation Kali

| Path | Loại | Vai trò |
|---|---|---|
| `~/Documents/vn-soc-lab/` | git clone | Repo dự án |
| `~/.secrets/credentials.md` | tạo mới | chmod 600 — copy local của Elastic/GitHub credentials |
| `~/.config/git/ignore` | sửa | Global gitignore `.secrets/` |
| `~/.claude/projects/-home-kali/memory/` | tạo mới | Memory Claude (user role, project context, references, feedback) |
| `~/.claude/settings.json` | sửa | Theme, `tui: "default"`, effortLevel |
| `~/.ssh/id_ed25519_vps` + `~/.ssh/config` (Pha 8) | tạo mới | Passwordless SSH to VPS |
| `autossh -R 0.0.0.0:9000:SOC-Tools:9000` (Pha 9) | runtime | Reverse tunnel TheHive bridge |
| `autossh -L 127.0.0.1:5678:127.0.0.1:5678` (Pha 9) | runtime | Local forward cho n8n UI |
| `~/Documents/vn-soc-lab/ml-detection/` | tạo mới | ML training scripts + Docker context (Pha 8) |
| `~/Documents/vn-soc-lab/soar/` | tạo mới | n8n / TheHive / bridge configs (Pha 9) |
| Package `autossh` | apt install | Persistent SSH tunnel daemon |

### 11.6 Trên GitHub

| Path | Loại | Vai trò |
|---|---|---|
| `gnid31/vn-soc-lab` repo | tạo mới | Private repo dự án |
| `main` branch | mặc định | Branch chính, mọi commit push thẳng |

---

## 12. Troubleshooting flow

Khi gặp lỗi, follow flowchart theo thứ tự — KHÔNG nhảy bước.

### 12.1 ES / Kibana / Logstash không start

```
sudo systemctl is-active <service>     # active hay failed?
  │
  ├── failed → sudo systemctl status <service> | tail -30
  │             ↓
  │             ├── "Out of memory" trong dmesg?
  │             │     → Heap quá lớn so với RAM VPS. Giảm /etc/elasticsearch/jvm.options.d/heap.options
  │             │
  │             ├── "Permission denied" /etc/.../keystore?
  │             │     → sudo chown root:elasticsearch /etc/elasticsearch/elasticsearch.keystore
  │             │     → sudo chmod 660 /etc/elasticsearch/elasticsearch.keystore
  │             │
  │             ├── "max virtual memory areas vm.max_map_count [65530] is too low"?
  │             │     → §4.2: echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.d/99-elasticsearch.conf
  │             │
  │             └── đọc log đầy đủ:
  │                   sudo tail -100 /var/log/<service>/<service>.log
  │
  └── active → service OK. Lỗi ở app/network layer (sang §11.2)
```

### 12.2 Kibana báo "Detection Engine permissions required"

→ Xem [§7.7](#77-kibana-báo-detection-engine-permissions-required--thực-ra-thiếu-encryption-keys). Fix: add 3 encryption keys vào keystore + restart Kibana.

### 12.3 Index `winlogbeat-*` trống / không có data

```
[1] Logstash có nhận event từ Beats không?
    curl -s http://localhost:9600/_node/stats/events?pretty | grep '"in"'
      ├── "in": 0 → endpoint chưa kết nối. Sang [2]
      └── "in": >0 → có nhận. Sang [3]

[2] Beats input 5044 listening?
    sudo ss -tlnp | grep :5044
      ├── không listen → Logstash chưa start hoặc pipeline lỗi. systemctl status logstash
      └── listen → endpoint phía Win10 chưa connect được
        ↓
        [2a] Test từ endpoint:
             PS> Test-NetConnection 43.228.215.234 -Port 5044
               ├── TcpTestSucceeded=False → UFW chặn? VPS provider firewall chặn?
               │     ssh namth@43.228.215.234 'sudo ufw status' | grep 5044
               └── TcpTestSucceeded=True → Winlogbeat config sai
        ↓
        [2b] Winlogbeat service status:
             PS> Get-Service winlogbeat
               ├── không Running → Start-Service winlogbeat
               └── Running → tail log:
                   PS> Get-Content "C:\ProgramData\winlogbeat\Logs\winlogbeat" -Tail 50
                     ├── "Connection refused" → VPS không nghe
                     ├── "no such host" → typo trong winlogbeat.yml hosts
                     └── "Connection established" → OK, sang [3]

[3] Logstash có output ra ES không?
    curl -s http://localhost:9600/_node/stats/events?pretty | grep -E '"(in|out)"'
      ├── "in" tăng nhưng "out" không → ES output lỗi. Tail log:
      │     sudo tail -50 /var/log/logstash/logstash-plain.log | grep -i error
      │     Thường thấy: password sai, ssl cert reject, ES không reachable
      └── "out" tăng → ES nhận. Sang [4]

[4] ES có index không?
    PASSWORD=$(grep '^password' ~/elastic-credentials.txt | cut -d= -f2 | tr -d ' ')
    curl -sk -u "elastic:$PASSWORD" "https://localhost:9200/_cat/indices/winlogbeat-*?v"
      ├── empty → check sau 5-10s (refresh interval). Nếu vẫn empty → ES disk full?
      │     curl -sk -u "elastic:$PASSWORD" https://localhost:9200/_cluster/allocation/explain?pretty
      └── có index → check docs.count > 0
```

### 12.4 Pipeline Logstash validate fail

```bash
sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
```

- `Expected one of #, [ \t\r\n], etc.` → syntax error. Tìm dòng error báo (line N column M).
- `Could not find plugin "translate"` → plugin chưa cài:
  ```bash
  sudo /usr/share/logstash/bin/logstash-plugin install logstash-filter-translate
  ```
- `Configuration OK` → restart safely.

### 12.5 Tail logs nhanh (1 lệnh xem 3 service)

```bash
sudo tail -F /var/log/{elasticsearch/elasticsearch,kibana/kibana,logstash/logstash-plain}.log
```

Ctrl+C để thoát.

---

*Báo cáo này được cập nhật theo nguyên tắc "deploy-then-document" — chỉ ghi nhận những gì đã thực thi xong. Các pha sắp tới xem [`roadmap.md`](roadmap.md). Lịch sử thay đổi: [`CHANGELOG.md`](CHANGELOG.md).*
