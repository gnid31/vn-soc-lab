# VN-SOC Lab — phần để chèn vào CV

> Định dạng giống template `CV.pdf` (Dự án SOC Lab / DFIR Lab / Pentest Lab style).
> Paste mục "Dự án VN-SOC Lab" vào section **WORK EXPERIENCE**, mục "Bổ sung" vào **SKILLS**.

---

## Dự án VN-SOC Lab — End-to-End SOC + SOAR + ML Detection

**06/2026 (~2 tuần solo)** · GitHub: `gnid31/vn-soc-lab`

**Mô tả:**

- Triển khai SIEM bare-metal Elasticsearch 8.19 + Kibana + Logstash trên VPS Cloud (Ubuntu 24.04), hardening UFW least-privilege, TLS internal self-signed cert, encryption keys vào Kibana keystore; ingest Sysmon (SwiftOnSecurity config + custom ProcessAccess RuleGroup cho LSASS detection) + Winlogbeat từ Windows 10 endpoint, sản lượng ~4400 event/ngày.
- Viết **9 detection rule KQL** trong Kibana Detection Engine ánh xạ **9 kỹ thuật MITRE ATT&CK** (T1059.001 PowerShell Encoded, T1003.001 LSASS Access, T1547.001 Registry Run Key, T1110 Brute Force, T1071.001 Non-Browser Outbound, T1595 Active Scanning, T1595.002 Suspicious UA, T1083 File Probe, T1190 Public-Facing App Exploit — ML-based).
- Mô phỏng adversary với **Atomic Red Team** chain T1547→T1059→T1110 trong 18 phút, sản xuất kill-chain narrative + viết Incident Report theo chuẩn **NIST 800-61 Rev2** (`VN-SOC-2026-0001`) với ProcessGuid pivot + IoC extract; tune false-positive R5 giảm 100% (exclude Antigravity `agy.exe`, OneDrive sync, SharePoint client).
- Mở rộng layer **Network IDS** bằng Suricata 8.0.5 + ET Open ruleset 50k+ signatures trên SOC-Tools VM, target DVWA Docker; refactor Logstash pipeline multi-branch routing (winlogbeat / suricata / dvwa-apache) với grok `COMBINEDAPACHELOG` + ECS v8 mapping.
- Triển khai **Wazuh HIDS full stack** (Manager + Indexer + Dashboard Docker) trên SOC-Wazuh VM, dual-SIEM coexistence pattern (Elastic primary + Wazuh secondary, Win10 endpoint dual-ship Winlogbeat + Wazuh Agent).
- Xây dựng **detection ML inline**: train classifier URL malicious (TF-IDF char n-gram + LogisticRegression scikit-learn, dataset 459 URL synthetic), deploy Flask + gunicorn Docker multi-stage trên VPS (mem_limit 400 MB), Logstash filter-http enrich mỗi DVWA event với `[ml]` object → R9 fire 9 alerts 100% TP ở threshold 0.7.
- Triển khai **SOAR đầy đủ**: TheHive 5.4 (Cassandra + ES 7) + n8n 1.74 + autossh reverse SSH tunnel cross-network + systemd timer poll ES alerts → n8n webhook (workaround Kibana Basic license không có `.webhook` connector). n8n workflow auto-extract observables (URL/IP/UA) từ alert payload → tạo TheHive case auto.
- Tích hợp **Cortex 3 threat-intel enrichment**: VirusTotal + AbuseIPDB analyzers free-tier; mỗi observable trong case được auto-run analyzer phù hợp (AbuseIPDB cho IP, VirusTotal cho URL/hash); end-to-end detect → case → enrich trong ~60-90 giây không cần thao tác tay.
- **Advanced detection engineering** — mở rộng lên **13 rules R1-R13 với 4/5 Kibana rule types** (query + threshold + EQL sequence + new_terms + indicator match). R10 EQL sequence rule bắt multi-stage attack (process_creation → network_connection → LSASS_access cùng host trong 10 phút) — behavioral detection thay signature. R12 new_terms baseline drift catch first-seen process image trên endpoint fleet.
- **Sigma rule authoring** — viết detection portable YAML + `sigma-cli` convert sang Elastic Lucene / EQL / ES|QL / Splunk SPL / Sentinel KQL. Portable across SIEM vendors, no lock-in.
- **Log enrichment pipeline production-grade** — Logstash filters: GeoIP src/dest IP (skip RFC1918 private) → `source.geo.location` (geo_point), `source.as.*` (ASN + org); useragent parser → `user_agent.name/os/device`; SHA256 fingerprint → `event.hash` dedup; URLhaus IOC feed 5000 malicious URL paths refresh daily via systemd timer → tag `ioc_match` matching events. R13 indicator match rule leveraging these tags.
- **Kibana ops production** — ILM policy 30-day rollover (hot 7d → warm shrink+forcemerge → delete 30d), index template + component template (`geo_point` mapping, `ignore_above: 8192` cho long PowerShell CommandLine), Data View source filters giảm 44→17 field per doc, runtime field Painless script (`attack_score = ml.score*100 + bonuses`), 6 saved searches Discover column presets, 3 dashboards + Kibana Maps (world attack sources) + Canvas exec workpad.
- Sản xuất **~3500 dòng docs Vietnamese dual-path GUI + CLI** (report.md + 7 file pha results + 13 rule spec + ELK-GUIDE.md + Sigma YAML) đảm bảo reproducibility — recruiter clone repo có thể tái triển khai trong ~6 giờ không cần AI agent.

**Outcomes đo lường được:**
- **13 detection rules** trải **11 MITRE ATT&CK techniques** (T1003/T1027/T1059/T1071/T1083/T1110/T1189/T1190/T1204/T1547/T1595); 4/5 Kibana rule types coverage.
- 34+ TheHive case auto-tạo từ smoke-test; observables auto-extracted + Cortex analyzer auto-run.
- 5000 URLhaus IOC feed refresh daily; Kibana Maps world heatmap 7+ external attack sources.
- Multi-host stack: 1 VPS + 4 VM (Kali / Win10 / SOC-Tools / SOC-Wazuh), ~14 Docker container chạy đồng thời.
- ELK ops: 30-day ILM policy, 3 custom dashboards + Maps + Canvas workpad, 6 saved searches + runtime field.

---

## Bổ sung phần SKILLS

> Paste vào các sub-section tương ứng trong SKILLS của CV gốc.

**SIEM & SOAR**
- Elasticsearch 8.19, Kibana, Logstash multi-branch pipeline
- Wazuh 4.9 full stack (Manager + Indexer + Dashboard)
- TheHive 5, Cortex 3, n8n workflow automation
- Logstash enrichment filters: geoip, useragent, translate (IOC feed), fingerprint (dedup), http (ML enrichment)
- Kibana ops: **ILM policy**, index template + component template, Data View source filters, **runtime fields** (Painless), saved objects export/import bundle, **Maps** (geo_point), **Canvas** (essql expressions)
- Threat intelligence feed integration: URLhaus (daily refresh via systemd timer)

**Detection Engineering**
- Kibana rule types mastered: **query, threshold, EQL sequence, new_terms, indicator match** (4/5)
- KQL / EQL / Lucene / ES|QL languages fluent
- **Sigma YAML** portable rule authoring + `sigma-cli` convert cross-SIEM
- ECS v8 schema — `event.code`, `source.geo.*`, `user_agent.*`, `threat.indicator.*`
- MITRE ATT&CK technique mapping (**11 techniques** deployed)
- Atomic Red Team adversary emulation + FP tuning iteratively
- ML-based detection (TF-IDF char n-gram + LogisticRegression, scikit-learn 1.5)
- Multi-stage attack detection via EQL sequence (`sequence by host.name with maxspan=10m [...]`)

**Endpoint & Network Telemetry**
- Sysmon (SwiftOnSecurity + custom ProcessAccess for LSASS), Winlogbeat
- Filebeat multi-source (Apache + Suricata)
- Suricata 8.0 NIDS + ET Open ruleset
- Wazuh Agent (MSI Windows + ossec.conf tuning)

**Container & Orchestration**
- Docker 29 + Docker Compose v5
- Multi-stage build (Python 3.12-slim), heap tuning (OpenSearch + Cassandra + ES 7)
- Network modes: bridge / host / extra_hosts; volume bind vs named

**Linux SysAdmin & Ops**
- systemd service + timer (oneshot, persistent), `loginctl enable-linger` for user services
- UFW least-privilege, TLS self-signed PKI flow, swap setup
- autossh reverse + local SSH tunnel, GatewayPorts config

**Programming & Automation**
- Python (scikit-learn ML pipeline, Flask + gunicorn, REST API auth flows)
- Bash scripting (one-shot reproducible deploy)
- KQL, jq, curl-based REST API CLI ops

**Documentation**
- NIST 800-61 Rev2 Incident Report format
- Dual-path docs (GUI ưu tiên + CLI equivalent), deploy-then-document protocol
- Markdown technical writing (~2700 lines for this lab)

---

## Phần OBJECTIVE — gợi ý cập nhật (giữ tên + giọng văn template CV gốc)

> Nếu muốn nâng tone OBJECTIVE để phản ánh khả năng hiện tại sau VN-SOC Lab:

*Sinh viên năm 4 ngành An toàn Hệ thống thông tin, đam mê Detection Engineering, DFIR và AI-in-Security. Đã tự xây dựng end-to-end SOC lab quy mô doanh nghiệp (9 detection rule mapping MITRE ATT&CK, dual-SIEM Elastic + Wazuh, ML inline enrichment, SOAR tự động với TheHive + n8n + Cortex). Mong muốn tìm vị trí thực tập sinh SOC / DFIR / AI Engineer để áp dụng + mở rộng kỹ năng vào môi trường thực tế.*

---

## Pre-interview talking points (chuẩn bị trước phỏng vấn)

| Câu hỏi possible | Trả lời tham khảo |
|---|---|
| "Khó nhất khi build lab này là gì?" | Cross-network bridging giữa VPS (Internet) và lab VMs (NAT vmnet8 private) — phải combine 3 thứ đồng thời: SSH `GatewayPorts yes` + `-R 0.0.0.0:9000` + Docker `network_mode: host` để n8n container reach TheHive qua tunnel. Mất ~45 phút debug, sản xuất 3 lessons learned trong pha9-results.md. |
| "Vì sao multi-SIEM thay vì all-in-one?" | Đây là pattern enterprise thật: Elastic mạnh về KQL flexibility + multi-source; Wazuh mạnh về HIDS + compliance modules (PCI, HIPAA built-in). Production team thường chạy parallel với khác vendor cho diversification. Lab này demo cả 2 stack cùng feed TheHive. |
| "Detection ML có thật không hay chỉ demo?" | Real model — TF-IDF char_wb (2,5) + LogReg balanced, 459 URL synthetic. 100% TP trên smoke-test (sqli/lfi/xss/.env/.git/wp-config). FP issue: dataset thiếu common .php benign → `/login.php` score 0.60 → mitigate bằng raise threshold 0.7 + plan augment với real Apache log. Demo MLOps iterability. |
| "License Kibana Basic không có .webhook connector — bạn solve thế nào?" | Viết Python systemd timer poll `.internal.alerts-security.alerts-default-*` mỗi 30s qua REST API, state file `/var/lib/vnsoc-soar/state.json` track last-seen timestamp restart-safe, forward sang n8n webhook localhost. Free-tier SOAR pattern phù hợp lab/SME — không tốn $$$ Gold license. |
| "Bạn có gặp issue nào với Cortex?" | 3 issues riêng: (1) ES container mem_limit 600m gây thrashing CPU 107% — bump 900m; (2) job_directory phải bind mount HOST path không named volume vì Cortex spawn sibling docker; (3) Cortex 3 CSRF strict — GUI bootstrap-only sau initial superadmin. Tất cả document trong pha9.5-results.md. |
| "Multi-stage attack bạn detect thế nào?" | R10 EQL sequence rule — `sequence by host.name with maxspan=10m` gộp 3 event tuần tự: process creation từ shell tool (powershell/cmd/wscript/rundll32) → outbound network connection port 80/443 → LSASS memory access (Sysmon Event 10). Fire alert CRITICAL với MITRE T1003.001 + T1059. Behavioral detection thay signature-based — bắt được attack chain chưa từng thấy. |
| "Sao dùng Sigma? Tại sao không viết KQL trực tiếp?" | Sigma YAML portable — 1 rule viết 1 lần, convert được sang KQL cho Elastic, SPL cho Splunk, KQL cho Sentinel, YAML cho ArcSight. Vendor lock-in giảm 100%. Team chuyển SIEM không phải rewrite rules. `sigma-cli` open-source từ SigmaHQ chuẩn hoá conversion. Lab tôi convert 2 Sigma → 4 backend outputs (Lucene, EQL, ES|QL, Splunk SPL). |
| "Threat intel feed integration production thế nào?" | 3-tier: (1) automatic IOC pull — URLhaus daily feed 5000 malicious URLs via `curl` + Python parser + Logstash `translate` dictionary; (2) tagging — Logstash filter match URL → add tag `ioc_match` + `threat.indicator.provider`; (3) detection — R13 Kibana rule fire khi match. Toàn bộ pipeline không cần external SaaS (không như MISP heavy). |
| "Analyst thấy log lóa quá — giải quyết thế nào?" | 4 layer optimize: (1) Data View **source filters** exclude 42 patterns noise (`agent.*`, `winlog.opcode`, duplicate raw fields) → giảm 44→17 field per doc; (2) field **popularity boost** — mark 22 core fields count=20 để show top Discover; (3) **saved searches** per event type với column preset; (4) **runtime field** `attack_score` compute at query time. Đo được: field visible giảm 61%. |

---

## Liên kết kèm CV (đề xuất)

```
GitHub:        github.com/gnid31/vn-soc-lab
README:        Architecture diagram Mermaid + 9 rule MITRE table + repo layout
Live demo:     (record theo DEMO.md script — 60-90s asciinema/OBS)
Main report:   report.md (1700+ dòng VI, dual-path GUI + CLI)
Detection:    detection-rules/ (9 KQL spec + NDJSON export)
```
