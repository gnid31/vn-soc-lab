# Pha 6 — Network Detection Layer Results

> Build SOC-Tools VM + Suricata IDS + DVWA target + Filebeat ship multi-source → ES.
> First expansion phase sau khi base lab Pha 1-5 hoàn tất.

**Ngày thực hiện:** 2026-06-26
**Thời gian:** ~3 giờ (bao gồm debug LVM + Logstash pipeline)
**Hardware change:** +1 SOC-Tools VM local (Ubuntu 22.04, 3 GB RAM, 23 GB disk)

---

## 1. Tóm tắt

Pha 6 mở rộng kiến trúc SIEM sang **network layer** + **web application layer** — đa nguồn log:

- **Suricata 8.0.5** native trên SOC-Tools VM monitor interface `ens33` (NAT segment vmnet8).
- **DVWA Docker** chạy port 8080 — vulnerable web target.
- **Filebeat 8.19** ship 2 nguồn (eve.json + Apache access.log) → VPS Logstash:5044.
- **Logstash pipeline updated** (`main.conf` replace `winlogbeat.conf`) — multi-branch routing:
  - Winlogbeat → `winlogbeat-*` (Pha 1 endpoint)
  - Filebeat + source_type=suricata → `suricata-*`
  - Filebeat + source_type=dvwa-apache → `dvwa-apache-*` (with `COMBINEDAPACHELOG` grok parse)

**Verify end-to-end:** Kali tấn công SQLi + sqlmap UA + Nikto UA + `.env` probe → Suricata fire **29 alerts** (gồm `ET INFO Possible Kali Linux hostname in DHCP` + `ET INFO Request to Hidden Environment File`) → ES nhận 199 Suricata docs + 33 DVWA Apache docs trong vài phút.

---

## 2. Architecture

```
LOCAL VMware (NAT vmnet8 — 192.168.154.0/24):

  Kali           192.168.154.151   attacker
  Win10 victim   192.168.154.xxx   endpoint
  SOC-Tools VM   192.168.154.165   sensor + web target

  Ubuntu 22.04 — 2 vCPU, 3 GB RAM, 23 GB disk:
    - Suricata 8.0.5 (native, monitor ens33)
    - Docker 29.6.0 + DVWA container (port 8080)
    - Filebeat 8.19.17 (2 inputs)

  ↓ Filebeat ship → VPS:5044

VPS 43.228.215.234:
    - Logstash main.conf (3 branches routing)
    - ES indices NEW:
        suricata-YYYY.MM.dd
        dvwa-apache-YYYY.MM.dd
```

---

## 3. Setup stages

### 3.1 Stage A — Extend LVM (gotcha: Ubuntu Server default chỉ alloc 50% disk)

Triệu chứng:
```
/dev/mapper/ubuntu--vg-ubuntu--lv  12G  47%
```

Mặc dù assign 20 GB disk lúc tạo VM, LVM chỉ tạo LV bằng ~50% (11.5 GB). Phần còn lại nằm trong VG "free space".

Fix:
```bash
sudo lvextend -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv
sudo resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv
df -h /
# → 23GB total, free 17GB
```

→ **Lesson:** mỗi VM Ubuntu Server mới phải kiểm tra LVM ngay sau install. Nếu không, sau vài ngày disk full mới phát hiện. Best practice: include `lvextend` trong cloud-init / post-install script.

### 3.2 Stage B — Docker install

Repo official Docker + Docker Compose plugin. Add user vào group `docker`:

```bash
# 1. Download GPG key + add repo (cần subshell vì curl + sudo pipe phức tạp)
sudo bash -c "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && chmod a+r /etc/apt/keyrings/docker.gpg"
sudo bash -c "echo 'deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable' > /etc/apt/sources.list.d/docker.list"

# 2. Install
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 3. Add user
sudo usermod -aG docker $USER

# 4. Verify
sudo docker run --rm hello-world
```

→ **Lesson — pipe sudo:** `curl ... | sudo ...` không hoạt động đúng. Phải dùng `sudo bash -c "..."` để toàn bộ pipeline chạy trong subshell có quyền root.

### 3.3 Stage C — Suricata + ET Open ruleset

PPA stable từ OISF (official Suricata maintainer):

```bash
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install -y suricata
suricata -V                        # → "Suricata version 8.0.5 RELEASE"
```

Config:
```bash
# Default monitor eth0, đổi sang ens33
sudo sed -i 's/interface: eth0/interface: ens33/g' /etc/suricata/suricata.yaml

# Update ruleset (ET Open)
sudo suricata-update
# → 66,804 rules loaded, 50,875 enabled

# Test config
sudo suricata -T -c /etc/suricata/suricata.yaml -v
# → Configuration provided was successfully loaded.

# Start + enable
sudo systemctl enable --now suricata
sudo systemctl is-active suricata    # → active
```

### 3.4 Stage D — DVWA Docker

File `~/soc-tools/dvwa/docker-compose.yml`:

```yaml
services:
  dvwa:
    image: vulnerables/web-dvwa
    container_name: vnsoc-dvwa
    ports:
      - "8080:80"
    restart: unless-stopped
    volumes:
      - ./apache-logs:/var/log/apache2
```

Lý do mount `./apache-logs` ra host: để Filebeat (chạy native trên host) đọc trực tiếp `access.log`, không cần `docker logs` API hay sidecar pattern.

```bash
cd ~/soc-tools/dvwa
sudo docker compose up -d
```

DVWA reachable tại `http://192.168.154.165:8080/` (HTTP 302 redirect → /setup.php).

### 3.5 Stage F — Filebeat 8.19.17

```bash
sudo bash -c "wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg"
sudo bash -c "echo 'deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main' > /etc/apt/sources.list.d/elastic-8.x.list"
sudo apt-get update
sudo apt-get install -y filebeat
```

Config trong `/etc/filebeat/filebeat.yml` (xem [`configs/filebeat-soc-tools.yml`](configs/filebeat-soc-tools.yml)) — 2 inputs:
1. `/var/log/suricata/eve.json` với ndjson parser + field `source_type: suricata`
2. `/home/gnid/soc-tools/dvwa/apache-logs/access.log` + field `source_type: dvwa-apache`

Output → `43.228.215.234:5044` (cùng port với Winlogbeat → cùng pipeline Logstash main.conf đa-branch).

**Permission issue:** Suricata `/var/log/suricata/` có mode `drwxrwx---` (0770) — chỉ user `suricata` đọc được. Filebeat chạy as root nhưng vẫn cần directory traverse permission. Fix:

```bash
sudo chmod 755 /var/log/suricata
sudo chmod 644 /var/log/suricata/eve.json
sudo sed -i "s|#filemode: 0600|filemode: 0644|" /etc/suricata/suricata.yaml
```

→ **Lesson:** Filebeat luôn xem service as root về quyền, nhưng path traversal vẫn cần directory bit + file readable bit. Sửa cả 2.

### 3.6 Stage G — VPS Logstash multi-branch pipeline

Replace `/etc/logstash/conf.d/winlogbeat.conf` bằng `main.conf` với 3 output branches:

```ruby
output {
  if [@metadata][beat] == "winlogbeat" or [agent][type] == "winlogbeat" {
    elasticsearch { ... index => "winlogbeat-%{+YYYY.MM.dd}" }
  }
  else if [@metadata][beat] == "filebeat" and [fields][source_type] == "suricata" {
    elasticsearch { ... index => "suricata-%{+YYYY.MM.dd}" }
  }
  else if [@metadata][beat] == "filebeat" and [fields][source_type] == "dvwa-apache" {
    elasticsearch { ... index => "dvwa-apache-%{+YYYY.MM.dd}" }
  }
  else {
    elasticsearch { ... index => "logstash-%{+YYYY.MM.dd}" }
  }
}
```

Filter chain mới cho 2 nguồn Filebeat:

```ruby
if [@metadata][beat] == "filebeat" {
  if [fields][source_type] == "suricata" {
    mutate { add_tag => ["suricata", "nids"] }
    if [event_type] {
      mutate { add_field => { "[event][action]" => "%{event_type}" } }
    }
  }
  else if [fields][source_type] == "dvwa-apache" {
    grok { match => { "message" => "%{COMBINEDAPACHELOG}" } }
    mutate { add_tag => ["dvwa", "web", "apache"] }
  }
}
```

Validate + restart:
```bash
sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
# → Configuration OK
sudo systemctl restart logstash
```

**Lưu ý — không cần mở thêm UFW port:** dùng chung port 5044 (đã mở cho Winlogbeat từ Pha 2). Field-based routing trong Logstash filter chain phân loại đúng index.

### 3.7 Stage H — Test attack flow Kali → DVWA

Từ Kali (192.168.154.151) tấn công SOC-Tools (192.168.154.165:8080):

```bash
# SQLi
curl "http://192.168.154.165:8080/vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271"

# sqlmap fingerprint UA
curl -H "User-Agent: sqlmap/1.7.2" "http://192.168.154.165:8080/?id=1+UNION+SELECT+null"

# Nikto fingerprint UA
curl -H "User-Agent: Mozilla/5.0 (Nikto)" "http://192.168.154.165:8080/"

# Directory bruteforce
for p in admin login.php phpmyadmin wp-admin backup .env config.php; do
  curl "http://192.168.154.165:8080/$p"
done

# nmap service scan
nmap -sV -p 8080 192.168.154.165
```

---

## 4. Verify end-to-end

### 4.1 ES indices

```
suricata-2026.06.26      199 docs, 2.3 MB
dvwa-apache-2026.06.26    33 docs, 82 KB
```

### 4.2 Suricata alerts (top 5 chronological)

```
2026-06-26T04:07:07  192.168.154.151 → 192.168.154.254
  [Potential Corporate Privacy Violation]
  ET INFO Possible Kali Linux hostname in DHCP Request Packet

2026-06-26T04:06:43  192.168.154.151 → 192.168.154.165
  [Misc activity]
  ET INFO Request to Hidden Environment File - Inbound

2026-06-26T04:06:43  192.168.154.165 → 192.168.154.151
  [Generic Protocol Command Decode]
  SURICATA HTTP Response excessive header repetition
```

→ **3 categories alerts** sinh ra: ET INFO (recon), ET SCAN (nmap UA earlier test), SURICATA internal protocol anomaly.

### 4.3 DVWA Apache log → Logstash grok → ES

Sample Apache document trong `dvwa-apache-*`:
```yaml
@timestamp : 2026-06-26T04:06:43.000Z
clientip   : 192.168.154.151
verb       : GET
request    : /vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271
response   : 302
agent      : curl/8.19.0
```

→ Grok `COMBINEDAPACHELOG` parse đúng — phân tách clientip, verb, request, response, agent thành ECS fields.

---

## 5. Lessons learned Pha 6

### 5.1 LVM trap — Ubuntu Server installer chỉ alloc 50% disk

Đã document ở §3.1. **Pre-check** mỗi VM mới: `df -h /` và `lvs`. Plan trước: dùng `lvextend +100%FREE` hoặc custom partition tại bước Ubuntu installer.

### 5.2 `curl | sudo` pipe broken

`curl ... | sudo dd of=...` thường KHÔNG hoạt động vì shell tách pipe trước khi sudo elevate. Đúng cách:

```bash
sudo bash -c "curl ... | tool ..."   # toàn pipeline trong subshell
# Hoặc:
curl ... -o /tmp/file && sudo install /tmp/file /etc/...
```

→ Đã gặp 2 lần trong Pha 6 setup (Docker GPG key + Elastic GPG key).

### 5.3 Filebeat permission cho directory với mode 0770

Mặc dù Filebeat chạy as root, vẫn cần directory `/var/log/suricata/` có execute bit cho "others" (`drwxr-xr-x` = 0755). `chmod 644 eve.json` không đủ — phải `chmod 755 /var/log/suricata/`.

### 5.4 Logstash multi-branch single port khả thi không cần thêm UFW

Pattern enterprise: 1 Beats input port, route bằng `[fields][source_type]` từ phía Beats client. Lợi:
- 1 UFW rule thay vì nhiều
- 1 monitoring point
- Field-based routing dễ test (đổi label trong filebeat.yml = không cần đụng firewall)

### 5.5 ET Open ruleset out-of-box rất rộng (50k+ rules) nhưng cần tune

66,804 rules tải về, 50,875 enabled. Phát hiện DHCP hostname Kali (`ET INFO Possible Kali Linux hostname in DHCP Request Packet`) — đây là INFO level, nếu tỉ lệ FP cao có thể disable. Pha 7+ sẽ tune theo môi trường lab.

### 5.6 PATH bị strip trong Bash sandbox automation

Trong session Claude Code Bash tool, đôi khi PATH bị reset thiếu `/usr/bin`/`/bin`. Workaround: dùng absolute path (`/usr/bin/curl`, `/bin/sleep`). Bài học cho automation script: **never trust PATH**, dùng absolute path cho mọi binary critical.

### 5.7 Logstash 8.x ECS v8 mode auto-rename grok fields

Khi xác nhận R7+R8 viết bằng KQL với field gốc của grok `COMBINEDAPACHELOG` (`clientip`, `verb`, `request`, `agent`, `response`), rule fire **0 alerts** dù 21+ docs matching ở ES.

**Root cause:** Logstash 8.x default có `pipeline.ecs_compatibility: v8` — auto-convert grok output sang ECS structure:

| Grok output field | Logstash 8.x ECS field |
|---|---|
| `clientip` | `source.address` |
| `verb` | `http.request.method` |
| `request` | `url.original` |
| `agent` | `user_agent.original` |
| `response` | `http.response.status_code` |
| `bytes` | `http.response.body.bytes` |

Đặc biệt **`agent` root field** bị Filebeat metadata overwrite (`agent: {type: filebeat, name: gnid, ...}`). KQL `agent: *sqlmap*` match Filebeat metadata KHÔNG match Apache UA.

**Cách verify field path trước khi viết KQL:**

```bash
curl -sk -u "elastic:$PW" "https://<ES>:9200/<index>/_search?size=1&pretty"
# Read _source structure → biết field path thực tế
```

**Workflow đề xuất:** sau khi grok parse, query 1 sample doc → ghi field map → mới viết KQL.

### 5.8 KQL syntax pitfalls — 4 bugs đã gặp khi viết R8

| # | Triệu chứng | Fix |
|---|---|---|
| a | `*.env*` 0 match dù `/.env` có trong data | URL là text field bị tokenize (slash + dot là separator). Dùng `url.original.keyword` (raw full-string) |
| b | `"*sqlmap*"` match literal string với asterisk | KQL: quotes biến wildcard thành literal. Bỏ quotes — viết `*sqlmap*` (unquoted) |
| c | `\.env` parse fail "invalid escape" | KQL: `.` không phải special char, `\.` invalid. Bỏ backslash — viết `.env` |
| d | `*.git/*` fail toàn query với EOF | Lucene parser hiểu `/*` là comment-open, scan tới `*/` không thấy → EOF. Tránh sequence `/*` — viết `*.git*` thay vì `*.git/*` |

**Quy tắc KQL cho text field path/URL:**

- Substring trong 1 token (vd `*sqlmap*` trong UA token `sqlmap/1.7.2`) → text OK
- Substring cross separator (vd `*.env*` trên URL `/.env`) → **`.keyword` bắt buộc**
- Aggregation / sort / threshold → `.keyword` bắt buộc
- Tránh `/*` sequence trong pattern → biến thành Lucene comment

---

## 6. Backlog cho Pha 6+ (sau khi base ổn)

### 6.1 Detection rules R6/R7/R8 trên Kibana (cần user GUI work)

| ID | Rule | KQL filter | Index pattern |
|---|---|---|---|
| R6 | Network scan detected | `event_type: "alert" AND alert.category: "Attempted Information Leak"` | `suricata-*` |
| R7 | Web shell upload attempt | `verb: POST AND request: *.php* AND response: 200` | `dvwa-apache-*` |
| R8 | Multi-source correlation — Suricata alert + DVWA 4xx spike | (cần composite query / EQL sequence rule) | both |

User tự tạo trên Kibana UI theo template `detection-rules/R1-*.md §5`.

### 6.2 Tune Suricata ruleset

- Disable noise rules: SURICATA HTTP Response excessive header repetition (internal anomaly, nhiều FP).
- Enable thêm rule groups: `emerging-exploit.rules`, `emerging-web_specific_apps.rules`.

### 6.3 Suricata `suricata.yaml` advanced tuning

- Enable `eve.types.tls` chi tiết hơn (JA3 fingerprint).
- Enable `eve.types.anomaly` để gather anomaly events.
- Adjust `outputs.eve-log.types.alert.metadata`: true để include rule metadata.

### 6.4 Lab limitation đã document

| Limitation | Workaround |
|---|---|
| Suricata không thấy Win10↔Kali lateral traffic | OK trong scope Pha 6 (focus web attack); Pha 7+ thêm Wazuh Agent endpoint detection bù |
| DVWA chỉ là 1 web target | Có thể thêm Juice Shop / WebGoat Pha 6.1 |
| ET Open free tier (không có ET Pro emerging-threats-pro) | OK cho lab; production phải subscribe |

---

## 7. Trạng thái Pha 6 cuối

| Hạng mục | Trạng thái |
|---|---|
| SOC-Tools VM tạo + boot + SSH | ✅ 192.168.154.165, Ubuntu 22.04 |
| LVM extended 12→23 GB | ✅ |
| Docker + Compose v5 | ✅ 29.6.0 |
| Suricata 8.0.5 + ET Open 50k rules | ✅ active monitor ens33 |
| DVWA Docker port 8080 | ✅ reachable từ Kali |
| Filebeat 8.19 + 2 inputs | ✅ ship Logstash:5044 |
| Logstash main.conf multi-branch | ✅ validate OK, restart OK |
| ES suricata-* index | ✅ 1000+ docs |
| ES dvwa-apache-* index | ✅ 57+ docs |
| **Detection rules R6/R7/R8 trên Kibana** | ✅ **verified 2026-06-27** |
| R6 Network Scan alerts | ✅ 4 alerts/5min smoke-test |
| R7 Suspicious UA alerts (sau 2 KQL fix) | ✅ 9 alerts |
| R8 Sensitive File Path alerts (sau 3 KQL fix) | ✅ 10 alerts |
| Rule schedule | ✅ tuned từ 5min→1min (lab cycle nhanh) |

---

## 8. Pha 6 Quick stats

| Metric | Giá trị |
|---|---|
| Time setup infrastructure (Stage A→H) | ~3 giờ |
| Time debug R7+R8 KQL (5 bugs ECS+syntax) | ~30 phút |
| Tổng rule trong Kibana sau Pha 6 | 8 (R1-R8) |
| Tổng MITRE tactic covered | 6 (Execution, Persistence, Credential Access, C2, Reconnaissance, Discovery) |
| Tổng MITRE technique covered | 8 (T1003, T1059, T1071, T1083, T1110, T1547, T1595, T1595.002) |
| Lessons learned mới Pha 6 | 2 (ECS field convert + KQL syntax) — đáng giá nhất cho recruiter interview |

---

*Pha 6 hoàn tất end-to-end. Sẵn sàng sang Pha 7 — Wazuh full stack HIDS trên SOC-Wazuh VM mới.*
