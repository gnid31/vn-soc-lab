# Detection Rules — Pha 3

Mỗi rule trong thư mục này là một file Markdown đặc tả + (sau khi import vào Kibana) một bản export NDJSON đi kèm.

## Convention chung — đặt tên & metadata

### Tên file + `rule_id` (kebab-case)

```
File   : R<N>-<TECHNIQUE-ID>-<slug>.md
rule_id: vnsoc-r<n>-<slug>
```

- `<TECHNIQUE-ID>`: dùng sub-technique nếu MITRE có (vd `T1059.001`), không thì parent (`T1110`).
- `<slug>`: 2–4 từ kebab-case, miêu tả ngắn.

### Display name (hiển thị trên Kibana)

```
[VN-SOC R<N>] <Technique description Title Case>
```

- Luôn prefix `[VN-SOC R<N>]` để filter dễ.
- Mô tả **technique-focused** (việc attacker làm), KHÔNG tactic-focused.
- Title Case, ≤ 70 ký tự.
- KHÔNG đưa threshold detail (vd "5 fails / 5 min") vào tên — đẩy xuống Description.

### Tags — 4 tag chuẩn

```
['VN-SOC-Lab', '<Tactic-PascalCase>', '<TechniqueID>', '<Concept-1-từ>']
```

| Tag # | Vai trò | Ví dụ |
|---|---|---|
| 1 | Identifier lab — filter tất cả rule lab này | `VN-SOC-Lab` (cố định) |
| 2 | MITRE Tactic, PascalCase | `Execution`, `Persistence`, `CredentialAccess`, `CommandAndControl`, `Discovery`, `LateralMovement`, `Exfiltration`, `Impact`, `InitialAccess`, `DefenseEvasion`, `PrivilegeEscalation`, `Collection`, `Reconnaissance`, `ResourceDevelopment` |
| 3 | MITRE Technique ID | `T1059.001`, `T1547.001`, `T1110`, `T1003.001`, `T1071.001` |
| 4 | Concept keyword 1 từ | `PowerShell`, `LSASS`, `RunKey`, `BruteForce`, `NonBrowser` |

### Severity ↔ Risk score

| Severity | Risk score | Khi nào dùng |
|---|---|---|
| Low | 21 | Recon, info gathering — không có hành vi gây hại |
| Medium | 47 | Persistence (chưa active), một số C2 beacon |
| High | 73 | Execution có context xấu, Brute force, Network connection từ binary lạ |
| Critical | 90 | Credential Access thành công (LSASS dump), Impact (ransomware, wipe) |

## Quy ước viết KQL trong VN-SOC Lab

Vì lab này:
- Winlogbeat ship qua **Logstash**, không qua Beats ingest pipeline → các trường ECS `process.*` **KHÔNG** được populate.
- Sysmon raw data nằm dưới `winlog.event_data.*`.
- `winlog.event_id` đang là `text` field — phải dùng `.keyword` cho aggregation. Cho `match` query thì cả 2 đều ok.
- Sử dụng `event.code` (đã ECS-mapped, type keyword) thay cho `winlog.event_id` khi có thể.

**Trường thường dùng nhất:**

| Mục đích | Trường KQL | Nguồn |
|---|---|---|
| Loại sự kiện Sysmon | `event.code: "1"` ... `"29"` | Winlogbeat |
| Provider | `winlog.provider_name: "Microsoft-Windows-Sysmon"` | Winlogbeat |
| Process image | `winlog.event_data.Image` | Sysmon e1, e3, e10, e11, e13... |
| Command line | `winlog.event_data.CommandLine` | Sysmon e1 |
| Parent image | `winlog.event_data.ParentImage` | Sysmon e1 |
| Parent command | `winlog.event_data.ParentCommandLine` | Sysmon e1 |
| Registry path | `winlog.event_data.TargetObject` | Sysmon e12, e13, e14 |
| File created | `winlog.event_data.TargetFilename` | Sysmon e11 |
| DNS query | `winlog.event_data.QueryName` | Sysmon e22 |
| Network destination | `winlog.event_data.DestinationIp`, `winlog.event_data.DestinationPort` | Sysmon e3 |
| User | `winlog.event_data.User` | Sysmon (mọi event) |
| Host | `host.name`, `host.hostname` | Winlogbeat |
| Tag VN-SOC Lab | `tags: "vn-soc-lab"` | Logstash pipeline |

## Workflow tạo rule mới

1. Viết spec `R<N>-T<X>-<slug>.md` với KQL + lý do + false-positive.
2. Trên Kibana → **Security → Rules → Detection rules → Create new rule**:
   - Rule type: **Custom query**.
   - Index pattern: `winlogbeat-*`.
   - Custom query: paste KQL từ spec.
   - About: name, severity, description, **MITRE ATT&CK tactic + technique**.
   - Schedule: 5 phút interval, look-back 10 phút.
   - Actions: tạm để trống (chỉ log internal alert).
3. Save & Enable.
4. Trigger thử bằng Atomic Red Team (Pha 4) hoặc lệnh thủ công.
5. Khi rule đã verify trigger được:
   - Trên Kibana → Rules → check rule → **Export rule** → tải về file NDJSON.
   - Đặt file NDJSON cùng tên spec, commit.

## Trạng thái 18 rule đăng ký (R1-R18)

| ID | Display name | MITRE | Type | Spec / NDJSON | Verify |
|---|---|---|---|---|---|
| R1 | `[VN-SOC R1] PowerShell Encoded Command Execution` | T1059.001 | query | [R1](R1-T1059.001-powershell-encoded.md) / [ndjson](R1-T1059.001-powershell-encoded.ndjson) | ✅ 5+1 alerts |
| R2 | `[VN-SOC R2] LSASS Memory Access` | T1003.001 | query | [R2](R2-T1003.001-lsass-access.md) / [ndjson](R2-T1003.001-lsass-access.ndjson) | ✅ 1 (Defender FP) |
| R3 | `[VN-SOC R3] Registry Run Key Modification` | T1547.001 | query | [R3](R3-T1547.001-registry-run-key.md) / [ndjson](R3-T1547.001-registry-run-key.ndjson) | ✅ 4 alerts |
| R4 | `[VN-SOC R4] Multiple Failed Logon — Brute Force` | T1110 | threshold | [R4](R4-T1110-brute-force-login.md) / [ndjson](R4-T1110-brute-force-login.ndjson) | ✅ 1 (sau fix threshold config) |
| R5 | `[VN-SOC R5] Non-Browser Outbound HTTP/HTTPS` | T1071.001 | query | [R5](R5-T1071.001-non-browser-outbound.md) / [ndjson](R5-T1071.001-non-browser-outbound.ndjson) | ✅ 55 → 0 sau tune (Antigravity + OneDrive + SharePoint exclude) |
| R6 | `[VN-SOC R6] Network Scan Detection` | T1595 | query | [R6](R6-T1595-network-scan.md) / [ndjson](R6-T1595-network-scan.ndjson) | ✅ 4 (suricata-*) |
| R7 | `[VN-SOC R7] Suspicious User-Agent — Web Attack Tool` | T1595.002 | query | [R7](R7-T1595.002-suspicious-ua.md) / [ndjson](R7-T1595.002-suspicious-ua.ndjson) | ✅ 9 (sau 2 KQL fix) |
| R8 | `[VN-SOC R8] Sensitive File Path Probe` | T1083 | query | [R8](R8-T1083-sensitive-file-probe.md) / [ndjson](R8-T1083-sensitive-file-probe.ndjson) | ✅ 10 (sau 3 KQL fix) |
| R9 | `[VN-SOC R9] ML Malicious URL Detection` | T1190 | query | [R9](R9-T1190-ml-malicious-url.md) / [ndjson](R9-T1190-ml-malicious-url.ndjson) | ✅ 9 alerts (100% TP — Pha 8 ML) |
| R10 | `[VN-SOC R10] Multi-Stage Attack — Process + Network + LSASS Sequence` | T1003.001 + T1059 | **EQL sequence** | [ndjson](R10.ndjson) | Pha 11 (EQL 10min window) |
| R11 | `[VN-SOC R11] Web Login Brute Force — Threshold` | T1110 | threshold | [ndjson](R11.ndjson) | Pha 11 (DVWA /login.php POST ≥ 20/5min) |
| R12 | `[VN-SOC R12] First-Seen Process Image on Endpoint` | T1204 | **new_terms** | [ndjson](R12.ndjson) | Pha 11 (14-day baseline drift) |
| R13 | `[VN-SOC R13] URLhaus IOC Match — Threat Intel` | T1189 | query | [ndjson](R13.ndjson) | Pha 11 (URLhaus feed 5000 IOCs) |
| R14 | `[VN-SOC R14] Wazuh FIM — Critical File/Registry Change` | T1547.001 + T1562.001 | query | [ndjson](R14.ndjson) | ✅ Pha 13 — 9 alerts (Startup + hosts) |
| R15 | `[VN-SOC R15] YARA Malware Detection` | T1105 + T1204 | query | [ndjson](R15.ndjson) | Pha 14 (YARA 9 rules, EICAR + malware families) |
| R16 | `[VN-SOC R16] Cowrie SSH Honeypot Interaction` | T1595 + T1110 | query | [ndjson](R16.ndjson) | Pha 14 — 4 alerts (Kali smoke-test) |
| R17 | `[VN-SOC R17] UEBA Behavioral Anomaly — Z-Score Baseline Drift` | T1078 | query | [ndjson](R17.ndjson) | Pha 14 (Python z-score ≥ 2.0) |
| R18 | `[VN-SOC R18] Vulnerability Scanner — Critical/High CVE Discovered` | T1190 + T1195 | query | [ndjson](R18.ndjson) | Pha 15 — 768 findings (89 CRITICAL + 679 HIGH) |

## Pitfalls / Lessons learned trong Pha 3

| # | Bài học | Rule liên quan | Detail |
|---|---|---|---|
| 1 | KQL wildcard fail trên text field có `\` hoặc space | R1 | Phải dùng `.keyword` cho path/command. Xem [R1 §2a](R1-T1059.001-powershell-encoded.md#2a-bài-học-quan-trọng--khi-nào-phải-dùng-keyword) |
| 2 | Threshold field vs Cardinality field trong Kibana UI | R4 | 2 setting nhìn giống nhau, đặt sai → rule không fire dù status=succeeded. Xem [R4 §2.2](R4-T1110-brute-force-login.md#22-threshold-setting) |
| 3 | "Known-good tool with malware-like behavior" | R5 | Antigravity (`agy.exe`) trong `%APPDATA%` gọi HTTPS → R5 fire 30 alerts đúng pattern beacon. Xem [R5 §4](R5-T1071.001-non-browser-outbound.md#4-false-positive-thường-gặp--cách-lọc) |
| 4 | Kibana "Detection Engine permissions required" thật ra do thiếu encryption keys | (toàn bộ) | Setup Kibana 8.x không tự sinh keys. Xem [report.md §6.7](../report.md) |
| 5 | KQL OR syntax pitfall — quên `OR` giữa item trong exclude list | R5 tune | status=succeeded KHÔNG đảm bảo logic. Acceptance test: query sample alert post-save. Xem [pha4-results §Lesson 5](../pha4-results.md) |
| 6 | Verify alert query time window quá hẹp → miss event | R2 verify | Atomic test event có thể ngoài window `now-30m` do shipping delay + rule schedule. Mở rộng range hoặc query no-time-filter. Xem [pha4-results §8](../pha4-results.md) |
| 7 | Logstash 8.x ECS v8 mode auto-convert grok fields | R7+R8 debug | Grok `COMBINEDAPACHELOG` ra `clientip/verb/request/agent` nhưng Logstash rename thành `source.address/http.request.method/url.original/user_agent.original`. Filebeat metadata cũng overwrite `agent` field root. Xem [R8 §2a](R8-T1083-sensitive-file-probe.md#2a-bài-học-kql-bugs-pha-6) |
| 8 | KQL syntax pitfalls: `.keyword` cho tokenize text, quote = literal, `\\.` invalid escape, `/*` Lucene comment | R7+R8 debug | Test KQL trên Discover trước khi gắn vào detection rule. 5 bugs đã gặp xem [R8 §2a](R8-T1083-sensitive-file-probe.md#2a-bài-học-kql-bugs-pha-6) |
