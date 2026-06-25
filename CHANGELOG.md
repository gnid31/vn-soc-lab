# CHANGELOG

> Append-only log. One line per meaningful change. Format:
> `[YYYY-MM-DD HH:MM] [actor=claude|antigravity|namth] [phase=N] mô tả ngắn`

[2026-06-25 02:00] [actor=claude] [phase=1] hoàn tất Pha 1 — cài Elasticsearch + Kibana + Logstash 8.19.17 trên VPS 43.228.215.234, heap ES 512MB
[2026-06-25 02:05] [actor=claude] [phase=1] cấu hình Logstash pipeline winlogbeat.conf — beats input 5044, ECS v8 filter, ES output https://localhost:9200
[2026-06-25 02:10] [actor=claude] [phase=1] mở UFW 5044/tcp (Beats) + 5601/tcp (Kibana); 9200 vẫn đóng
[2026-06-25 02:20] [actor=claude] [phase=2] chuẩn bị prompt cho Antigravity setup Sysmon + Winlogbeat trên Win10 (xem roadmap.md §A.1)
[2026-06-25 02:30] [actor=claude] [phase=0] init repo private vn-soc-lab; tách docs cũ thành report.md + roadmap.md theo nguyên tắc deploy-then-document
