# CHANGELOG

> Append-only log. One line per meaningful change. Format:
> `[YYYY-MM-DD HH:MM] [actor=claude|antigravity|namth] [phase=N] mô tả ngắn`

[2026-06-25 02:00] [actor=claude] [phase=1] hoàn tất Pha 1 — cài Elasticsearch + Kibana + Logstash 8.19.17 trên VPS 43.228.215.234, heap ES 512MB
[2026-06-25 02:05] [actor=claude] [phase=1] cấu hình Logstash pipeline winlogbeat.conf — beats input 5044, ECS v8 filter, ES output https://localhost:9200
[2026-06-25 02:10] [actor=claude] [phase=1] mở UFW 5044/tcp (Beats) + 5601/tcp (Kibana); 9200 vẫn đóng
[2026-06-25 02:20] [actor=claude] [phase=2] chuẩn bị prompt cho Antigravity setup Sysmon + Winlogbeat trên Win10 (xem roadmap.md §A.1)
[2026-06-25 02:30] [actor=claude] [phase=0] init repo private vn-soc-lab; tách docs cũ thành report.md + roadmap.md theo nguyên tắc deploy-then-document
[2026-06-25 13:35] [actor=antigravity] [phase=2] hoàn tất cài đặt và cấu hình Sysmon + Winlogbeat trên Win10, kết nối Logstash:5044 thành công
[2026-06-25 14:10] [actor=claude] [phase=2] verify Pha 2 từ VPS — Logstash events_in=4493, ES index winlogbeat-2026.06.25 có 4417 docs, hostname DESKTOP-L7FCMBQ, tags đầy đủ; bổ sung §5.4 vào report.md
[2026-06-25 14:30] [actor=claude] [phase=2] audit Sysmon — 2675 docs, breakdown event_id 1/3/11/13/22; ghi §5.4.1 + §5.4.2 phát hiện event.action override bởi Winlogbeat processor + winlog.event_id là text field không aggregate được trực tiếp
[2026-06-25 14:45] [actor=claude] [phase=3] scaffold detection-rules/ — README (cookbook + bảng KQL field map cho Sysmon raw) + spec R1 PowerShell EncodedCommand làm template. Các rule còn lại (R3/R4/R5) sẽ do namth tự viết spec theo cùng template khi tạo trên Kibana UI
[2026-06-25 15:30] [actor=claude] [phase=2] fix Kibana Detection Engine: thêm 3 encryption keys (xpack.encryptedSavedObjects, xpack.reporting, xpack.security) vào kibana-keystore, restart Kibana. Phát hiện qua log "Unable to create alerts client because the Encrypted Saved Objects plugin is missing encryption key"
[2026-06-25 15:45] [actor=claude] [phase=2] rewrite report.md comprehensive (12 gap reproducibility) — thêm §0 Prerequisites + §10 File Inventory + §11 Troubleshooting; expand §4 với Linux pre-check + Kibana keystore (§4.7); expand §5 với URL đầy đủ + winlogbeat.yml inline + Win10 verify; thay sample doc bằng Sysmon e1 (rundll32) real; thêm §6.7 incident encryption keys. Total 631 → 906 dòng
[2026-06-25 14:32] [actor=namth] [phase=3] manual create rule R1 trên Kibana UI — [VN-SOC R1] PowerShell EncodedCommand Execution, severity High, MITRE TA0002→T1059→T1059.001, schedule 5m/look-back 10m
[2026-06-25 14:40] [actor=namth] [phase=3] fix R1 UI — tags từ 1-string thành 3 tag riêng (VN-SOC-Lab/T1059.001/PowerShell), thêm MITRE sub-technique T1059.001
[2026-06-25 14:32] [actor=namth] [phase=3] smoke-test R1 — chạy powershell.exe -EncodedCommand (Write-Host benign) trên Win10 endpoint DESKTOP-L7FCMBQ
[2026-06-25 14:45] [actor=claude] [phase=3] diagnose KQL R1 không match — root cause: Image.keyword chứ không phải Image (text field tokenize backslash → wildcard miss). Đề xuất KQL fix
[2026-06-25 14:47] [actor=namth] [phase=3] update KQL R1 theo fix .keyword + manual run rule
[2026-06-25 14:49] [actor=claude] [phase=3] verify R1 fire alert thành công — 1 alert tạo trong .internal.alerts-security.alerts-default-000001 khớp 100% smoke-test event (host=DESKTOP-L7FCMBQ, Image=powershell.exe, CommandLine=-EncodedCommand+payload). End-to-end pipeline Logstash → ES → Kibana Detection Engine verified
[2026-06-25 15:00] [actor=claude] [phase=3] update detection-rules/R1 spec — final KQL, §2a bài học .keyword vs text field cho path/command, §4a smoke-test timeline + alert verify, status ✅ deployed+verified; detection-rules/README bảng status R1 enabled+verified 2026-06-25
[2026-06-25 16:00] [actor=claude] [phase=3] viết spec R2/R3/R4/R5 — template same R1, mỗi spec có §1 lý do, §2 KQL final, §4 FP, §5 Kibana config bước, §6 smoke-test (R2 defer Pha 4), §7 verify path
[2026-06-25 16:30] [actor=claude] [phase=3] standardize naming convention — display name [VN-SOC R<N>] <Title Case>, tags 4 chuẩn [VN-SOC-Lab, <Tactic>, <TechniqueID>, <Concept>], severity-risk mapping, file naming kebab. Apply hết 5 spec + README convention section
[2026-06-25 16:45] [actor=claude] [phase=3] thêm Description block đồng bộ vào 4 spec còn thiếu (R2/R3/R5 và R4), tất cả có dòng "Tham khảo: detection-rules/<file>.md"
[2026-06-25 17:00] [actor=namth] [phase=3] tạo 4 rule R2/R3/R4/R5 trên Kibana UI theo convention mới + rename R1 từ "EncodedCommand" → "Encoded Command" + thêm tag Execution
[2026-06-25 17:30] [actor=antigravity] [phase=3] chạy smoke-test 4 rule (R1+R3+R4+R5) trên Win10 — payload benign, không tắt Defender. R4 test với 6 net use cùng username VnSocBruteTest, R5 test với Invoke-WebRequest example.com
[2026-06-25 17:45] [actor=claude] [phase=3] verify smoke-test từ VPS — R1/R3/R5 fire alert đúng. R4 KHÔNG fire dù có 18 events: root cause = config trap Cardinality field thay vì Threshold field (group-by). R5 fire 30 alerts với 30/30 từ agy.exe (Antigravity) — bài học known-good tool có hành vi giống malware
[2026-06-25 18:00] [actor=namth] [phase=3] fix R4 config trên Kibana UI — move TargetUserName.keyword từ Cardinality → Threshold field; re-trigger 6 net use; R4 fire 1 alert đúng
[2026-06-25 18:15] [actor=claude] [phase=3] BATCH commit cuối Pha 3 — update status header 4 spec (R2/R3/R4/R5), thêm Pitfall section vào R4 spec (Cardinality vs Threshold), document observed FP agy.exe vào R5 spec, update detection-rules/README status table 5/5 + Pitfalls section 4 lessons learned; roadmap: Pha 3 ✅, Pha 4 includes R2 test + R5 tuning

