# Pha 13 — File Integrity Monitoring (FIM)

> Wazuh syscheck FIM trên Win10 endpoint + custom rules Manager + Filebeat ship
> alerts sang Elastic → unified Kibana view multi-SIEM. Cover T1547.001
> persistence + T1562.001 defense evasion + T1098 account manipulation.

**Ngày thực hiện:** 2026-06-27
**Thời gian:** ~1.5 giờ (gồm Gemini agent điều khiển Win10 config)
**Hardware change:** +1 Filebeat process trên SOC-Wazuh VM (~50MB RAM)

---

## 1. Tóm tắt

Pha 13 close gap của Pha 7 "future work" — ship Wazuh alerts sang Elastic để unified Kibana view.

**Deploy scope (option B — Win10 focus):**
- Enable Wazuh Agent syscheck trên Win10 (registry + startup folder + hosts + tasks).
- Custom Wazuh Manager rules 100010-100016 cho vn-soc-lab specific paths + Windows registry Run keys.
- Filebeat 8.19 trên SOC-Wazuh VM host tail `/var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.json` → VPS Logstash :5044.
- Logstash multi-branch: `wazuh-alerts` fields → index `wazuh-alerts-YYYY.MM.dd`.
- Kibana R14 detection rule fire khi Wazuh syscheck level ≥ 7.

**Deferred (SOC-Tools + VPS Linux agents):**
- Config files ready trong `fim/linux/syscheck-additions.xml` — deploy khi bạn muốn expand.

**Verify E2E:**
- Win10 add file Startup + modify hosts → 15 Wazuh syscheck events → ship qua Filebeat → 15 docs `wazuh-alerts-2026.07.01` → **R14 fired 9 alerts** trong Kibana Detection Engine.

---

## 2. Architecture delta

```
LOCAL VMware (192.168.154.0/24):
  Win10 (192.168.154.164)
    Wazuh Agent 4.9.2 syscheck enabled:
      - C:\Windows\System32\drivers\etc         (realtime)
      - C:\Users\ADMIN\...\Startup              (realtime, T1547.001)
      - C:\ProgramData\...\Startup              (realtime, T1547.001)
      - C:\Windows\System32\Tasks               (realtime)
      - HKLM\Software\...\Run + RunOnce         (registry FIM)
      - HKCU\Software\...\Run + RunOnce
      - HKLM\Software\...\Windows Defender\Exclusions (T1562.001)
    │
    │ Wazuh proto :1514 (data) + :1515 (enrollment)
    ▼
  SOC-Wazuh VM (192.168.154.163)
    Wazuh Manager Docker
      /var/ossec/etc/rules/local_rules.xml  (custom rules 100010-100016)
      /var/ossec/logs/alerts/alerts.json    (all alerts NDJSON)
    │
    │ (Docker volume mount → host path)
    ▼
    /var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.json
    │
    │ Filebeat 8.19 tail filestream input
    │ ship qua TCP 5044 (Beats)
    ▼

VPS (43.228.215.234):
  Logstash main.conf branch [fields][source_type] == "wazuh-alerts"
    → tag by rule.groups
    → output index wazuh-alerts-YYYY.MM.dd
  ES ILM policy vnsoc-30d applied
  Kibana:
    Data view wazuh-alerts-*
    R14 detection rule (rule.id 550 OR 100010-100016)
```

---

## 3. Setup stages

> **Dual-path convention:** Stage 3.1 (Wazuh custom rules) + Stage 3.4 (Kibana rule R14) có cả **GUI ưu tiên** + CLI. Stage 3.2 (Win10 agent ossec.conf) là **GUI + PowerShell dual-path** — Wazuh Dashboard có Agent Group config UI cho centralized but lab dùng edit file trực tiếp. Stage 3.3 (Filebeat) là **CLI-only** — Linux service file-based.

### 3.1 Custom Wazuh Manager rules — `local_rules.xml`

7 rules ID 100010-100016 cover:

| Rule ID | Level | Trigger | MITRE |
|---|---|---|---|
| 100010 | 12 | `/etc/passwd|shadow|sudoers` modified | T1098 Account Manipulation |
| 100011 | 12 | `authorized_keys` modified | T1098.004 SSH Authorized Keys |
| 100012 | 12 | SIEM stack config (`/etc/logstash|elasticsearch|kibana`) tampered | T1562.001 Impair Defenses |
| 100013 | 10 | Cron / systemd unit modified | T1053.003 + T1543.002 |
| 100014 | 12 | Windows Registry Run key modified | T1547.001 Boot/Logon Autostart |
| 100015 | 10 | Windows Startup folder file added | T1547.001 |
| 100016 | 14 | Windows Defender exclusion registry tampered | T1562.001 |

**GUI (Wazuh Dashboard):**
1. Wazuh Dashboard → **Management → Rules → Custom rules**.
2. Click **"local_rules.xml"** → paste content.
3. Save + auto-reload manager.

**CLI:**
```bash
sshpass -p '1' scp fim/wazuh-manager/local_rules.xml gnid@192.168.154.163:/tmp/
sshpass -p '1' ssh gnid@192.168.154.163 'docker cp /tmp/local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml && docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml && docker restart single-node-wazuh.manager-1'
```

### 3.2 Enable Win10 syscheck

**GUI (Wazuh Dashboard Agent Group — production standard):**
1. Wazuh Dashboard → **Management → Groups → "windows" group → Configuration**.
2. Edit `agent.conf` với syscheck block. Auto-apply cho agents in group.

**CLI (edit ossec.conf trực tiếp — lab shortcut):** xem `fim/win10/syscheck-additions.xml`. Chèn vào Win10 agent config file, restart WazuhSvc. Có thể dùng AI agent (Gemini/Antigravity) chạy PowerShell — xem prompt trong conversation history.

**Key config points:**
- `realtime="yes"` cho critical paths (Startup, hosts, drivers/etc).
- `report_changes="yes"` để Wazuh capture DIFF không chỉ hash change.
- `<windows_registry>` cho persistence keys T1547.001.
- `frequency 1800` (30 phút) scan cycle full — lab tune từ default 12h.

### 3.3 Filebeat ship Wazuh alerts → Logstash

**CLI-only:**
```bash
# Install Filebeat 8.19 (same version as Elastic stack)
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update && sudo apt install -y filebeat=8.19.17
```

**Config `filebeat.yml`** (see `fim/soc-wazuh/filebeat.yml`):
```yaml
filebeat.inputs:
  - type: filestream
    id: wazuh-alerts
    paths:
      - /var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.json
    parsers:
      - ndjson: { keys_under_root: true, add_error_key: true }
    fields: { source_type: wazuh-alerts }

output.logstash:
  hosts: ["43.228.215.234:5044"]
```

**Logstash pipeline branch** (added in `configs/main.conf`):
```ruby
if [fields][source_type] == "wazuh-alerts" {
  mutate { add_tag => ["wazuh", "hids"] }
  mutate { add_field => { "[event][category]" => "endpoint" } }
  mutate { add_field => { "[event][module]" => "wazuh" } }
  # Tag by Wazuh rule.groups
  if [rule][groups] {
    ruby {
      code => 'event.get("[rule][groups]").each { |g| event.tag(g) } if event.get("[rule][groups]").is_a?(Array)'
    }
  }
}
```

Output index `wazuh-alerts-YYYY.MM.dd` + ILM policy `vnsoc-30d` applied auto.

### 3.4 R14 Kibana Detection Rule

**GUI (ưu tiên):**
1. Kibana → **Security → Rules → Create → Custom query**.
2. Data view: `wazuh-alerts-*`.
3. Query: `(rule.id : "550" OR rule.id : ("100010" OR "100011" OR ... OR "100016")) AND rule.level >= 7`.
4. Severity: High, risk 73. Schedule 1m/5m.
5. MITRE T1547.001 + T1562.001.

**CLI:** POST tới `/api/detection_engine/rules` (xem export `detection-rules/R14.ndjson`).

### 3.5 Smoke-test end-to-end

**Win10 PowerShell as Admin:**
```powershell
# Test 1: Startup folder — T1547.001 persistence
"echo VN-SOC test" | Out-File "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\vnsoc-fim-test.txt"

# Test 2: Registry Run key
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "vnsoc-fim-test" -Value "notepad.exe" -PropertyType String -Force

# Test 3: Modify hosts file
Add-Content "C:\Windows\System32\drivers\etc\hosts" "`n# VN-SOC FIM test"

# Wait ~60s for pipeline: Agent → Manager → alerts.json → Filebeat → Logstash → ES → R14

# Cleanup
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\vnsoc-fim-test.txt"
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "vnsoc-fim-test"
```

**Kết quả smoke-test thực tế:**

```
Wazuh Manager alerts.json    → 15 syscheck events
wazuh-alerts-2026.07.01 ES  → 15 docs indexed
R14 detection rule fire      → 9 alerts (Startup folder + hosts file)
Rule 550 (default FIM)       → hosts file modified
Rule 100015 custom           → Startup file added/deleted
```

---

## 4. Lessons learned (Pha 13)

| # | Lesson | Detail |
|---|---|---|
| 1 | Wazuh Docker alerts.json path | Docker volume mount `/var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.json`. Filebeat trên HOST đọc trực tiếp, không cần vào container. |
| 2 | Filebeat filestream + ndjson parser | Wazuh alerts.json là NDJSON (1 JSON object per line). Dùng `parsers: - ndjson: keys_under_root: true` để Logstash nhận structured. Bad: parse plain text → mất structure. |
| 3 | Wazuh Manager restart để reload rules | Custom rules trong `/var/ossec/etc/rules/local_rules.xml` → cần `docker restart single-node-wazuh.manager-1`. Không có SIGHUP reload rules. |
| 4 | Windows Registry FIM chậm hơn file FIM | Startup folder file (`realtime="yes"`) alert trong 5-10s. Registry key add alert chậm hơn (10-30s) vì Windows Registry API polling based, không realtime true. |
| 5 | Wazuh default rule 550 khá noisy | Windows Update Task file thay đổi liên tục → rule 550 lvl=7 fire mỗi vài phút. Filter R14 KQL AND `rule.level >= 7` — vẫn noisy, có thể tune AND `path : *drivers/etc* OR path : *Startup*` để giảm FP. |
| 6 | Rule groups tag via Logstash ruby | `event.get("[rule][groups]").each { |g| event.tag(g) }` — expand array Wazuh rule.groups thành individual tags. Dễ filter dashboard `tags: "syscheck"`. |
| 7 | Ship-back topology quan trọng | Wazuh HIDS + Elastic SIEM = 2 stack độc lập → ship alerts qua Filebeat = ELIMINATION swiss-cheese. Analyst nhìn 1 Kibana dashboard cover cả 2 SIEM signals — production pattern. |

---

## 5. Files sản phẩm

| File | Nội dung |
|---|---|
| `fim/win10/syscheck-additions.xml` | Config block chèn vào Win10 `ossec.conf` — directories + registry keys |
| `fim/linux/syscheck-additions.xml` | Config cho Linux Wazuh Agent (SOC-Tools/VPS defer) — /etc critical + /opt/vnsoc-* |
| `fim/wazuh-manager/local_rules.xml` | 7 custom rules ID 100010-100016 |
| `fim/soc-wazuh/filebeat.yml` | Filebeat config ship Wazuh alerts → Logstash :5044 |
| `configs/main.conf` | Updated: wazuh-alerts filter branch + output index |
| `detection-rules/R14.ndjson` | Exported R14 rule cho reproducibility |
| `pha13-results.md` | Doc này |

---

## 6. Trạng thái Pha 13 cuối

| Component | Status |
|---|---|
| Wazuh Agent syscheck config Win10 | ✅ 4 dirs realtime + 5 registry keys |
| Wazuh Manager custom rules (100010-100016) | ✅ deployed |
| Filebeat 8.19 SOC-Wazuh | ✅ active, ship alerts.json |
| Logstash wazuh-alerts filter branch | ✅ pipeline running |
| ES index wazuh-alerts-* | ✅ ILM policy applied |
| Kibana data view wazuh-alerts-* | ✅ created |
| R14 detection rule | ✅ **9 alerts fired trong smoke-test** |
| Total rules trong lab | **14** (R1-R14) |

**Deferred (option B scope):**
- SOC-Tools Linux Wazuh Agent (config ready, deploy khi VM on)
- VPS Wazuh Agent + reverse tunnel 1514/1515 setup

---

## 7. Quick stats

| Metric | Value |
|---|---|
| Detection rules total | **14** (R1-R14) |
| Wazuh custom rules | 7 (100010-100016) |
| Directories monitored (Win10) | 4 realtime + 1 non-realtime |
| Registry keys monitored | 5 (Run/RunOnce ×4 + Defender exclusions) |
| MITRE techniques added Pha 13 | T1098, T1098.004, T1053.003, T1543.002 (up to **15 total lab-wide**) |
| Time end-to-end deploy + smoke-test | ~1.5 giờ |
| Filebeat RAM footprint | ~50 MB |
| Lessons learned | 7 new |

---

## 8. Verify via Kibana GUI

### Wazuh alerts trong Kibana (unified dual-SIEM view)
1. **Discover → wazuh-alerts-*** → thấy 15+ docs từ Win10 syscheck.
2. Add column `agent.name`, `rule.id`, `rule.level`, `rule.description`, `syscheck.path`, `syscheck.event`.
3. Filter `rule.groups : "syscheck"` → FIM-only events.
4. Filter `rule.id : ("550" OR "100015")` → default FIM + custom Startup folder rule.

### R14 detection rule
1. **Security → Alerts** → filter `kibana.alert.rule.name : "*R14*"` → thấy 9 alerts từ smoke-test (Startup file added/deleted + hosts modified).
2. Click alert → panel → xem full `syscheck` block với `path`, `event`, `sha256_after` (if content changed).

### Wazuh Dashboard (native UI, complement Kibana)
1. Browser → `https://192.168.154.163` → login admin.
2. Wazuh menu → **Modules → Integrity monitoring** → xem timeline agent DESKTOP-L7FCMBQ với file/registry changes.
3. Modules → **Security events** → filter rule.id 100010-100016 → xem custom rules fire.

---

*Pha 13 hoàn tất. FIM layer thêm vào SIEM stack. Wazuh HIDS + Elastic SIEM dual-view Kibana unified. CV story: multi-vendor SIEM ship-back pattern.*
