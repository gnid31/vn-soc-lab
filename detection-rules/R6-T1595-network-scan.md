# R6 — Network Scan Detection (Suricata)

| Thuộc tính | Giá trị |
|---|---|
| Rule ID | `vnsoc-r6-network-scan` |
| MITRE Tactic | TA0043 — Reconnaissance |
| MITRE Technique | **T1595** Active Scanning |
| Severity | **Medium** |
| Risk score | 47 |
| Index pattern | `suricata-*` |
| Rule type | Custom query (KQL) |
| Schedule | Every 1 minute, look-back 5 minutes (lab cycle nhanh) |
| Status | ✅ Deployed + verified 2026-06-27 (4 alerts trong 5 phút smoke-test) |

## 1. Vì sao detect cái này

Active scanning (nmap, masscan, zmap) là **bước đầu tiên** của hầu hết tấn công external. Attacker từ Internet hoặc lateral inside scan dải IP → discover host + service. ET Open ruleset có 100+ signature cho scan patterns:

- `ET SCAN` category — bộ rule chuyên cho recon
- `ET INFO` category — info-level events có ý nghĩa recon (vd Kali hostname trong DHCP)
- `Attempted Information Leak` — class các signature liên quan info gathering
- `Web Application Attack` — class các web-attack signature

Detect sớm scan = SOC analyst có cơ hội block attacker IP trước khi họ pivot vào exploit phase.

## 2. KQL query

```
event_type: "alert" AND
alert.category: (
  "Attempted Information Leak" OR
  "Misc activity" OR
  "Web Application Attack" OR
  "Potentially Bad Traffic"
) AND
alert.signature: (
  *SCAN* OR
  *Nmap* OR
  *masscan* OR
  *Recon* OR
  *probe* OR
  *enum*
)
```

**Giải thích:**

- `event_type: "alert"` — chỉ event_type=alert trong eve.json (Suricata cũng log flow/http/dns/tls mà KHÔNG phải alert).
- `alert.category` — Suricata classifications của ET ruleset. 4 categories trên là umbrella cho scan/recon.
- `alert.signature` substring — bắt thêm các rule không thuộc 4 category trên nhưng có keyword scan trong tên.

→ Combined condition giảm noise (alerts ngoài scope) đồng thời cover broad scan patterns.

## 3. Ví dụ event match (đã observed Pha 6)

```yaml
event_type    : alert
src_ip        : 192.168.154.151          (Kali)
dest_ip       : 192.168.154.254          (broadcast/gateway)
proto         : UDP
alert.signature: ET INFO Possible Kali Linux hostname in DHCP Request Packet
alert.category : Potential Corporate Privacy Violation
```

Hoặc:

```yaml
event_type    : alert
src_ip        : 192.168.154.151
dest_ip       : 192.168.154.165
alert.signature: ET SCAN Possible Nmap User-Agent Observed
alert.category : Web Application Attack
```

## 4. False-positive thường gặp

| FP scenario | Đặc trưng | Khuyến nghị |
|---|---|---|
| Internal IT vulnerability scan tools (Nessus, Qualys, OpenVAS) | src_ip = subnet IT/Sec ops | Whitelist `src_ip: ("10.x.x.x" OR ...)` cho scanner approved |
| Network discovery agents (network monitoring tool) | Service signature có pattern probe nhưng từ trusted host | Verify hash + path |
| Cloud health-check / load balancer probes | Cùng src_ip, very high frequency | Threshold tăng hoặc whitelist nếu xác định LB |

## 5. Cấu hình rule trong Kibana

> ⚠️ **Trước khi tạo rule:** vào **Stack Management → Data Views → Create data view** với name `suricata-*`, timestamp field `@timestamp`. Nếu không có data view, rule sẽ fail.

1. Kibana → **Security → Rules → Detection rules → Create new rule**.
2. **Custom query** rule type.
3. **Source: Data View** → chọn `suricata-*`.
4. **Custom query**: paste KQL ở §2.
5. **Continue** → About rule:
   - **Name**: `[VN-SOC R6] Network Scan Detection`
   - **Description**:
     ```
     Phát hiện activity scan từ Suricata IDS — nmap, masscan, hoặc ET SCAN
     signatures khác. T1595 Active Scanning là phase đầu của hầu hết
     external attack — detect sớm = cơ hội block attacker IP trước khi
     họ pivot sang exploit phase.
     Tham khảo: detection-rules/R6-T1595-network-scan.md
     ```
   - **Severity**: Medium
   - **Risk score**: 47
   - **Tags**: `VN-SOC-Lab`, `Reconnaissance`, `T1595`, `Suricata`
   - **MITRE ATT&CK threats**:
     - Tactic: `Reconnaissance (TA0043)`
     - Technique: `Active Scanning (T1595)`
6. **Continue** → Schedule:
   - Runs every: **5 minutes**
   - Additional look-back time: **5 minutes** (tổng look-back 10 phút)
7. **Continue** → Actions: bỏ qua.
8. **Create & enable**.

## 6. Smoke-test (an toàn — chỉ recon, không exploit)

Từ Kali (không qua AI agent):

```bash
# 1. nmap với version detection — fire ET SCAN rules
nmap -sV -p 8080 192.168.154.165

# 2. Force Nmap user-agent qua HTTP request
curl -H "User-Agent: Mozilla/5.0 (Nmap)" "http://192.168.154.165:8080/"
curl -H "User-Agent: Nikto" "http://192.168.154.165:8080/"

# 3. Banner grab
curl -I "http://192.168.154.165:8080/"
```

**Đợi ≤5 phút** → Kibana → Security → Alerts → thấy alert R6 từ Suricata.

## 7. Khi rule verified

- Export NDJSON → `detection-rules/R6-T1595-network-scan.ndjson`.
- Update header status: ✅ Deployed + verified `<date>`.
- Append CHANGELOG.
