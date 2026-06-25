# VN-SOC Lab — Roadmap

> **Mục đích:** ghi lại **kế hoạch** các pha sắp tới + design notes. Khi 1 hạng mục được triển khai xong, di chuyển nội dung sang [`report.md`](report.md) (đã verify thật), KHÔNG chỉ copy.

---

## Tổng quan 5 pha

| Pha | Tên | Tuần | Trạng thái |
|---|---|---|---|
| 1 | SIEM Backend Deployment | T1 D1–D3 | ✅ Hoàn tất (xem report) |
| 2 | Endpoint Telemetry | T1 D4–D5 | ✅ Hoàn tất (xem report) |
| 3 | Detection Engineering | T1 D6–T2 D2 | ✅ Hoàn tất (5 rule deployed, 4 smoke-tested, R2 defer Pha 4) |
| 4 | Adversary Emulation | T2 D3–D4 | 🔄 Sẵn sàng — bao gồm test R2 + tune R5 FP `agy.exe` |
| 5 | Incident Response & Documentation | T2 D5–D7 | ⏳ Pending |

---

## A. Pha 2 — Endpoint Telemetry (kế hoạch)

### A.1 Prompt cho Antigravity (chạy trên Win10)

> ⚠️ Prompt này KHÔNG chứa password Elastic — Winlogbeat chỉ nói với Logstash:5044, không cần credential ES.

````
Hãy cài và cấu hình Sysmon + Winlogbeat trên máy Windows 10 này
để ship log về VN-SOC Lab.

THÔNG SỐ LAB:
- Logstash Beats input: 43.228.215.234:5044   (TCP, không TLS phía Beats)
- KHÔNG dùng output.elasticsearch — lab này thu mọi log qua Logstash để
  enrich & normalize tập trung. Output Winlogbeat phải là output.logstash.

YÊU CẦU TRIỂN KHAI THEO THỨ TỰ:

[1] Tải Sysmon (Microsoft Sysinternals)
   - URL: https://download.sysinternals.com/files/Sysmon.zip
   - Giải nén vào C:\Sysmon
   - Tải config SwiftOnSecurity:
     https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
   - Cài: Sysmon64.exe -accepteula -i sysmonconfig-export.xml
   - Verify: Get-Service Sysmon64 phải Running, StartType = Automatic
   - Verify event đang sinh ra:
     Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5

[2] Tải Winlogbeat 8.x (PHẢI khớp major.minor với Elastic, lab dùng 8.19)
   - URL: https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.19.0-windows-x86_64.zip
   - Giải nén vào "C:\Program Files\Winlogbeat"

[3] Ghi đè file winlogbeat.yml (backup file cũ thành winlogbeat.yml.bak trước):

# === BEGIN winlogbeat.yml ===
winlogbeat.event_logs:
  - name: Application
  - name: System
  - name: Security
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4103, 4104, 4105, 4106

output.logstash:
  hosts: ["43.228.215.234:5044"]

tags: ["vn-soc-lab", "endpoint-win10", "<HOSTNAME>"]

logging.level: info
logging.to_files: true
logging.files:
  path: C:\ProgramData\winlogbeat\Logs
  name: winlogbeat
  keepfiles: 7
  permissions: 0644

monitoring.enabled: false
# === END winlogbeat.yml ===

Trước khi save: thay <HOSTNAME> bằng $env:COMPUTERNAME thực tế.

[4] Test config syntax:
   cd "C:\Program Files\Winlogbeat"
   .\winlogbeat.exe test config -e
   .\winlogbeat.exe test output -e
   Cả hai PHẢI trả về "OK" mới sang bước 5.

[5] Đăng ký Winlogbeat thành Windows service (PowerShell as Administrator):
   .\install-service-winlogbeat.ps1
   Start-Service winlogbeat
   Get-Service winlogbeat        # phải Running

[6] Sanity check end-to-end:
   - Trigger 1 process creation: notepad.exe rồi đóng
   - Đợi 30 giây
   - Tail log:
     Get-Content "C:\ProgramData\winlogbeat\Logs\winlogbeat" -Tail 30
   - PHẢI thấy dòng:
     "Connection to backoff(async(tcp://43.228.215.234:5044)) established"

[7] Báo cáo lại:
   - Service Sysmon64 status
   - Service winlogbeat status
   - 5 dòng cuối winlogbeat log
   - Output của: .\winlogbeat.exe version

LƯU Ý AN TOÀN:
- KHÔNG tắt Windows Defender ở Pha 2 — chỉ tắt khi sang Pha 4 (Atomic Red Team).
- KHÔNG chạy payload tấn công nào ở bước này.
- Nếu Defender chặn tải Sysmon → thêm exclusion cho C:\Sysmon, không tắt toàn bộ AV.
````

### A.2 Verify từ phía VPS sau khi Win10 ship event đầu tiên

```bash
# Logstash events counter — events.in PHẢI > 0
curl -s http://localhost:9600/_node/stats/events?pretty | grep '"in"'

# Index winlogbeat-* đã tạo
curl -sk -u elastic:<ELASTIC_PASSWORD> \
  "https://localhost:9200/_cat/indices/winlogbeat-*?v"

# Sample document
curl -sk -u elastic:<ELASTIC_PASSWORD> \
  "https://localhost:9200/winlogbeat-*/_search?size=1&pretty"
```

Trong Kibana → Discover → tạo index pattern `winlogbeat-*` → sẽ thấy event đầu tiên.

### A.3 Khi hoàn tất Pha 2

Di chuyển nội dung sang `report.md` §5:
- Cập nhật bảng A.1.2 (trạng thái Sysmon, Winlogbeat, index)
- Ghi command output thực tế đã chạy
- Thêm screenshot Kibana Discover nếu có

---

## B. Pha 3 — Detection Engineering (kế hoạch)

**Mục tiêu:** ≥5 detection rule trong Kibana, mỗi rule mapping MITRE ATT&CK.

### B.1 Danh sách rule dự kiến

| # | Rule | MITRE Technique | Query mẫu (KQL) |
|---|---|---|---|
| R1 | PowerShell EncodedCommand | T1059.001 | spec viết xong → [detection-rules/R1](detection-rules/R1-T1059.001-powershell-encoded.md) |
| R2 | LSASS access (Mimikatz-style) | T1003.001 | `event.action: process_access AND winlog.event_data.TargetImage: *lsass.exe*` |
| R3 | Registry Run Key persistence | T1547.001 | `event.action: registry_value_set AND registry.path: *Run*` |
| R4 | Brute-force login | T1110 | `event.action: logon_failed` threshold ≥5 trong 1 phút cùng `user.name` |
| R5 | Outbound từ process không-phải-browser | T1071 | `event.action: network_connection AND NOT process.name: (chrome.exe OR msedge.exe OR firefox.exe)` |

### B.2 Quy trình tạo

1. Kibana → **Security → Rules → Create new rule**.
2. **Custom query** rule type → KQL từ bảng trên.
3. **About**: gán MITRE ATT&CK Tactics & Techniques (Kibana có dropdown chuẩn).
4. **Schedule**: chạy 5 phút/lần, look-back 10 phút.
5. **Actions**: tạm chỉ log internal.
6. Save & Enable.

### B.3 Deliverable Pha 3

- `detection-rules/R1-T1059.001.md` (1 file/rule với query + lý do + false-positive note).
- Export NDJSON của tất cả rule (Kibana → Rules → Export) commit vào `detection-rules/`.

### B.4 False-positive lưu ý

| Rule | FP phổ biến | Giảm thiểu |
|---|---|---|
| R1 | Tool admin dùng Base64 hợp pháp (SCCM, GPO scripts) | Loại process parent là `svchost.exe`/`gpscript.exe` |
| R2 | Antivirus tự đọc LSASS để check | Whitelist theo `process.executable` đã ký số AV |
| R3 | Software update tự thêm Run key | Whitelist domain ký số (vd Microsoft Corp) |
| R4 | RDP từ Bastion hợp lệ | Loại nguồn từ IP subnet quản trị |
| R5 | Update agent (chocolatey, winget) | Whitelist process name của package manager đã biết |

---

## C. Pha 4 — Adversary Emulation (kế hoạch)

**Mục tiêu:** ≥3 Atomic Red Team test, mỗi test trigger ≥1 rule từ Pha 3.

### C.1 Test khuyến nghị

| Test | Technique | Lệnh | Rule kỳ vọng |
|---|---|---|---|
| Atomic T1059.001-1 | PowerShell EncodedCommand | `Invoke-AtomicTest T1059.001 -TestNumbers 1` | R1 |
| Atomic T1547.001-1 | Reg Run Key | `Invoke-AtomicTest T1547.001 -TestNumbers 1` | R3 |
| Atomic T1071.001 | C2 over Web Protocol | `Invoke-AtomicTest T1071.001` | R5 |

### C.2 Quy trình 1 vòng test (BẮT BUỘC)

```powershell
# 1. Snapshot VM Win10 trước test
# 2. Tắt tạm Defender (CHỈ trong test, snapshot trước!)
Set-MpPreference -DisableRealtimeMonitoring $true
# 3. Chạy test
Invoke-AtomicTest <Tx> -TestNumbers <N>
# 4. Đợi 1-2 phút, vào Kibana → Security → Alerts xem rule trigger
# 5. CLEANUP (rất quan trọng):
Invoke-AtomicTest <Tx> -TestNumbers <N> -Cleanup
# 6. Bật lại Defender
Set-MpPreference -DisableRealtimeMonitoring $false
# 7. Verify Defender đã bật:
Get-MpPreference | Select-Object DisableRealtimeMonitoring  # phải False
```

### C.3 Bằng chứng cần thu thập

- Screenshot Kibana → Alerts table có timestamp khớp test.
- Screenshot Discover với raw event JSON.
- Bảng kết quả test (time-to-detect):

| Test | Đã chạy | Rule trigger | Time-to-detect |
|---|---|---|---|
| T1059.001-1 | | | |
| T1547.001-1 | | | |
| T1071.001 | | | |

---

## D. Pha 5 — Incident Response (kế hoạch)

**Mục tiêu:** Viết Incident Report theo format doanh nghiệp cho 1 chuỗi tấn công đa-bước.

### D.1 Template Incident Report (rút gọn)

```
INCIDENT REPORT — VN-SOC-2026-0001

Severity:       High
Status:         Contained
Date detected:  YYYY-MM-DD HH:MM UTC+7
Reporter:       namth (SOC Analyst T1)

[EXECUTIVE SUMMARY]   3-5 dòng, ngôn ngữ business

[KILL CHAIN MAPPING]
1. Initial Access     → T1566.001
2. Execution          → T1059.001
3. Persistence        → T1547.001
...

[TIMELINE]
14:23  ...

[IOC]
- File: ...
- Domain: ...
- Registry: ...

[CONTAINMENT ACTIONS]

[LESSONS LEARNED]

[APPENDICES]
A. Raw Sysmon events
B. Kibana Discover query
C. Screenshot alerts
```

### D.2 Deliverable Pha 5

| File | Đường dẫn |
|---|---|
| `incident-report-vn-soc-2026-0001.md` | `incidents/` |
| README repo bằng tiếng Anh (cho recruiter quốc tế) | `README.md` |
| CV bullet (2-3 dòng) | `cv-snippet.md` (top-level) |

---

## E. MITRE ATT&CK Coverage Map (mục tiêu cuối Pha 4)

| Tactic | Technique | Rule | Trạng thái |
|---|---|---|---|
| Initial Access | T1566.001 Phishing | (giả lập trong Pha 5) | ⏳ |
| Execution | T1059.001 PowerShell | R1 | ⏳ |
| | T1059.003 Windows CMD | — | backlog |
| Persistence | T1547.001 Run Keys | R3 | ⏳ |
| | T1053.005 Scheduled Task | — | backlog |
| Credential Access | T1003.001 LSASS Memory | R2 | ⏳ |
| | T1110 Brute Force | R4 | ⏳ |
| Discovery | T1057 Process Discovery | — | backlog |
| Command and Control | T1071.001 Web Protocol | R5 | ⏳ |

**Mục tiêu cuối:** 5/13 technique có detection rule trong scope 2 tuần. Backlog ghi rõ phần để mở rộng pha 6+.

---

## F. Pha 6+ — Mở rộng (nếu còn thời gian)

Không thuộc scope 2 tuần, nhưng có thể bổ sung sau:

- **F.1** Wazuh Manager forward alert sang Elastic (FIM, rootkit detection).
- **F.2** Suricata + pfSense → Filebeat → Logstash (network IDS).
- **F.3** TheHive + Cortex cho case management.
- **F.4** n8n SOAR workflow tự động enrich IOC qua VirusTotal/AbuseIPDB.
- **F.5** ML-based NIDS — train RandomForest/XGBoost trên CICIDS2017, deploy Flask API → tích hợp Kibana via webhook (vế "AI Engineer" của CV).

---

## G. Hardening backlog (đề xuất production)

| # | Hardening | Cách làm |
|---|---|---|
| 1 | Kibana HTTPS | Reverse proxy nginx + Let's Encrypt, hoặc `server.ssl.*` |
| 2 | Beats TLS | `ssl => true` ở Logstash input + ship client cert |
| 3 | ES cert verify | Mount `http_ca.crt`, `verification_mode: full` |
| 4 | RBAC + Spaces | Tạo role `soc-analyst-readonly`, tách space per team |
| 5 | Password manager | Vault, SOPS, hoặc sealed-secrets |
| 6 | UFW source CIDR | `ufw allow from <VPN_CIDR> to any port 5601` |
| 7 | Memory lock heap | `bootstrap.memory_lock: true` + `LimitMEMLOCK=infinity` |
| 8 | ILM index lifecycle | Hot → warm → cold; delete sau 30 ngày |
