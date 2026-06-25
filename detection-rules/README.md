# Detection Rules — Pha 3

Mỗi rule trong thư mục này là một file Markdown đặc tả + (sau khi import vào Kibana) một bản export NDJSON đi kèm. Quy ước đặt tên:

```
R<N>-T<MITRE_TECHNIQUE>-<slug>.md      ← spec & lý do
R<N>-T<MITRE_TECHNIQUE>-<slug>.ndjson  ← export Kibana (commit khi đã enable rule trên UI)
```

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

## Trạng thái 5 rule đăng ký

| ID | Tên | MITRE | Spec | Đã enable trên Kibana | Verify trigger |
|---|---|---|---|---|---|
| R1 | PowerShell EncodedCommand | T1059.001 | [R1](R1-T1059.001-powershell-encoded.md) | ✅ | ✅ 2026-06-25 |
| R2 | LSASS access (Mimikatz-style) | T1003.001 | _backlog_ | — | — |
| R3 | Registry Run Key persistence | T1547.001 | [R3](R3-T1547.001-registry-run-key.md) | ⏳ | ⏳ |
| R4 | Brute-force login | T1110 | _backlog_ | — | — |
| R5 | Non-browser outbound | T1071 | _backlog_ | — | — |

R2/R4/R5 sẽ được thêm khi R1+R3 đã verified trigger và viết được Incident Report mẫu.
