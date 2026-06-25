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

