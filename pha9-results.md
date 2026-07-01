# Pha 9 — SOAR & Case Management Results

> Auto-pipeline detection alert → case management: Kibana Detection Engine →
> ES alerts index → forwarder service (free-tier workaround vì basic license
> không có .webhook connector) → n8n webhook → TheHive 5 case (auto).

**Ngày thực hiện:** 2026-06-27
**Thời gian:** ~3 giờ (gồm 4 lần debug: TheHive args, perms, network bridging, n8n GET vs POST)
**Hardware change:** SOC-Tools VM RAM 2→4 GB; +3 Docker containers VPS (n8n) + SOC-Tools (Cassandra, ES, TheHive)

---

## 1. Tóm tắt

Pha 9 hoàn thiện vòng end-to-end của SOC: từ detection (Pha 3-8) → **SOAR & Case Management** (Pha 9).

- **TheHive 5.4** (Cassandra 4 + Elasticsearch 7 + TheHive) trên SOC-Tools VM.
- **n8n 1.74** workflow automation trên VPS.
- **SSH reverse tunnel** từ Kali bridge VPS:127.0.0.1:9000 → SOC-Tools:9000 (cross-network).
- **Alert forwarder service** (Python + systemd timer mỗi 30s) poll ES alerts → POST n8n webhook (free-tier replace for `.webhook` Kibana connector).
- **n8n workflow** parse alert payload → POST TheHive `/api/v1/case` với Header Auth Bearer token.

**Verify end-to-end:** trigger fresh DVWA attacks từ Kali → Suricata + DVWA Apache log → ES alerts (R6/R7/R8/R9 fire) → forwarder pick up → n8n → TheHive case auto-created với severity, tags, source reference. **34 cases tổng cộng** sau smoke-test (33 từ replay R6-R9 history + 1 fresh-attack case #34).

---

## 2. Architecture (cuối Pha 9 — kiến trúc đầy đủ lab)

```
LOCAL VMware (NAT vmnet8 192.168.154.0/24):

  Kali             192.168.154.151
    │  ssh -R 0.0.0.0:9000:192.168.154.165:9000 vps  (autossh)
    │  ssh -L 5678:127.0.0.1:5678 vps               (autossh, optional GUI access)
    │
    ├─ attack DVWA → http://192.168.154.165:8080/...
    │
    └─ TheHive UI → http://192.168.154.165:9000  (analyst view cases)

  Win10            192.168.154.164  (Winlogbeat + Wazuh agent — Pha 1/7)
  SOC-Tools VM     192.168.154.165
    ├─ Suricata (Pha 6)
    ├─ DVWA Docker :8080 (Pha 6)
    └─ TheHive stack Docker (Pha 9):
        ├─ thehive-cassandra :9042   (Cassandra 4.1.4, heap 512m)
        ├─ thehive-elasticsearch :9200 (ES 7.17.27, heap 512m)
        └─ thehive :9000  (TheHive 5.4.0)
  SOC-Wazuh VM     192.168.154.163  (Wazuh stack — Pha 7)

VPS 43.228.215.234:
  ├─ Elastic (Pha 1): ES :9200, Kibana :5601, Logstash :5044
  ├─ ml-url-api Docker :5000 loopback (Pha 8)
  ├─ n8n Docker network_mode:host, :5678 loopback (Pha 9)
  └─ vnsoc-soar.service (systemd, every 30s):
       poll ES .internal.alerts-security.alerts-default-*
       → POST http://127.0.0.1:5678/webhook/kibana-alert
       → n8n workflow:
           1. Webhook trigger
           2. Function: parse → TheHive case payload
           3. HTTP POST http://127.0.0.1:9000/api/v1/case (via SSH tunnel → SOC-Tools)
           4. Respond to webhook
       → TheHive case #N created
```

---

## 3. Setup stages

> **Dual-path convention:** Stage A (VM RAM upgrade) qua VMware GUI. Stage B/C/D (n8n + TheHive + bootstrap) có cả GUI (browser localhost URL) + CLI (Docker compose + REST API) — đa số stages **GUI ưu tiên** vì n8n workflow builder + TheHive admin UI đẹp. Stage E (SSH tunnel) + G (systemd timer) là **CLI-only** (network/service admin). Stage F (n8n workflow) là **GUI-only** với JSON export cho version control.

### 3.1 Stage A — Upgrade SOC-Tools RAM 2→4 GB

**GUI (ưu tiên):**
1. VMware → SOC-Tools VM → **VM → Power → Shut Down Guest**.
2. **VM → Settings → Memory → 4096 MB → OK**.
3. **Power On**.
4. SSH verify: `ssh gnid@192.168.154.165 'free -h | head -2'` → `Mem: 3.8Gi`.

**CLI alternative (vmrun, ít dùng):**
```bash
vmrun -T ws stop "/path/to/SOC-Tools.vmx" soft
# edit .vmx: memsize = "4096"
vmrun -T ws start "/path/to/SOC-Tools.vmx"
```

### 3.2 Stage B — Deploy n8n trên VPS

**CLI (chuẩn cho remote VPS):**
```bash
mkdir -p ~/soar/n8n && cd ~/soar/n8n
# docker-compose.yml — xem soar/n8n/docker-compose.yml
N8N_PWD=$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)
echo "N8N_BASIC_AUTH_PASSWORD=$N8N_PWD" > .env && chmod 600 .env
docker compose up -d
```

⚠️ **Lesson 1:** n8n 1.x deprecated `N8N_BASIC_AUTH_*` env vars. Lần đầu truy cập sẽ phải hoàn tất user management wizard (email, name, password). Không có cách bypass — phải GUI setup owner account.

**GUI (lần đầu setup wizard):**
1. Browser → `http://127.0.0.1:5678` (qua SSH tunnel local).
2. Điền owner: email + first/last name + password mạnh.
3. Lưu password vào `~/.secrets/credentials.md` (chmod 600).
4. Skip "Personalize".

### 3.3 Stage C — Deploy TheHive 5 stack trên SOC-Tools

**Sysctl tune (CLI-only):**
```bash
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-thehive.conf
sudo sysctl --system
```

**Boot stack:**
```bash
cd ~/soar/thehive
TH=$(openssl rand -base64 48 | tr -d '\n')
echo "THEHIVE_SECRET=$TH" > .env && chmod 600 .env
docker compose up -d   # đợi ~2 phút cho TheHive schema init
```

⚠️ **Lesson 2:** `docker-compose.yml` ban đầu mình copy từ docs cũ TheHive 4 với flags `--storage-type localfs --storage-localfs-location` — KHÔNG tồn tại trong TheHive 5. Container restart loop. Đúng: `--storage-directory /data/files` + `--no-config-cortex`. Verify args bằng `docker logs thehive | head` — TheHive 5 print full usage khi args sai.

### 3.4 Stage D — TheHive bootstrap: org + analyst user + API key

**GUI (ưu tiên) qua http://192.168.154.165:9000:**
1. Login default: `admin@thehive.local` / `secret`.
2. Đổi password ngay (Profile → Change password).
3. **Admin → Organisations → New** → name `vn-soc-lab`.
4. **Admin → Users → New** → login `soc@vn-soc-lab.local`, org `vn-soc-lab`, profile `org-admin`, set password.
5. **Re-login dưới user soc** → Profile → **Generate API key** → copy.

**CLI alternative (Pha 9 mình dùng vì reproducibility):**
```bash
# Login admin → cookie
curl -s -X POST http://127.0.0.1:9000/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin@thehive.local","password":"secret"}' -c /tmp/c.txt

# Change admin password
curl -s -X POST http://127.0.0.1:9000/api/v1/user/admin@thehive.local/password/set \
  -b /tmp/c.txt -H "Content-Type: application/json" \
  -d '{"password":"<NEW_ADMIN_PWD>"}'

# Create org + user + key
curl -s -X POST http://127.0.0.1:9000/api/v1/organisation -b /tmp/c.txt \
  -H "Content-Type: application/json" \
  -d '{"name":"vn-soc-lab","description":"VN-SOC Lab org","taskRule":"default","observableRule":"default"}'

curl -s -X POST http://127.0.0.1:9000/api/v1/user -b /tmp/c.txt \
  -H "Content-Type: application/json" \
  -d '{"login":"soc@vn-soc-lab.local","name":"SOC Analyst","organisation":"vn-soc-lab","profile":"org-admin"}'

curl -s -X POST http://127.0.0.1:9000/api/v1/user/soc@vn-soc-lab.local/password/set \
  -b /tmp/c.txt -H "Content-Type: application/json" -d '{"password":"<USER_PWD>"}'

curl -s -X POST http://127.0.0.1:9000/api/v1/user/soc@vn-soc-lab.local/key/renew \
  -b /tmp/c.txt -H "Content-Type: application/json"   # → returns API key string
```

⚠️ **Lesson 3:** Default `admin@thehive.local` là **system admin**, KHÔNG có permission `manageCase/create`. Phải tạo org + user role `org-admin` hoặc `analyst` mới có quyền tạo case. Lần đầu mình thử curl với admin key → 403 Forbidden.

### 3.5 Stage E — SSH reverse tunnel Kali → VPS → TheHive

VPS không reach được 192.168.154.0/24 (private NAT). Kali là máy duy nhất ở giữa.

```bash
# Trên Kali — install autossh nếu chưa có
sudo apt install -y autossh

# Enable GatewayPorts trên VPS để bind 0.0.0.0
ssh vps 'sudo sed -i "s/^#GatewayPorts no/GatewayPorts yes/" /etc/ssh/sshd_config && sudo systemctl reload ssh'

# Bind tunnel ra 0.0.0.0:9000 trên VPS
autossh -M 0 -f -N \
  -o "ServerAliveInterval=30" -o "ExitOnForwardFailure=yes" \
  -R "*:9000:192.168.154.165:9000" vps
```

⚠️ **Lesson 4:** Mặc định `GatewayPorts no` → SSH `-R` chỉ bind 127.0.0.1. Docker container ở custom bridge network không reach được host 127.0.0.1 (different namespace). Phải enable GatewayPorts + bind 0.0.0.0 ĐỒNG THỜI dùng `network_mode: host` cho n8n container — container share host network namespace mới reach loopback tunnel.

### 3.6 Stage F — n8n workflow: Webhook → Parse → TheHive POST

**GUI (chỉ cách thực tế, n8n no CLI workflow editor):**
1. Browser `http://127.0.0.1:5678` (SSH tunnel local).
2. **Workflows → Add → Import from File** → `soar/n8n/workflow-kibana-to-thehive.json`.
3. Double-click node **"TheHive: Create Case"**:
   - **Method**: `POST` ⚠️ (lesson 5)
   - **URL**: `http://127.0.0.1:9000/api/v1/case`
   - **Authentication**: Generic Credential Type → Header Auth → **Create New** → Name: `Authorization`, Value: `Bearer <API_KEY>`.
   - **Send Body**: JSON, expression preserves from Function node output.
4. Save → toggle **Active ON**.
5. Click Webhook node → tab Settings → copy **Production URL** → `http://localhost:5678/webhook/kibana-alert`.

⚠️ **Lesson 5:** n8n HTTP Request node default Method = **GET**. Workflow JSON mình import không có field `"method": "POST"` → n8n default GET → TheHive `/api/v1/case` chỉ support POST → trả **404** (không phải 405). Mất 30 phút debug vì error message "resource not found" misleading. Always explicitly set `method: POST` trong workflow JSON.

### 3.7 Stage G — Free-tier replace cho Kibana Webhook connector

⚠️ **Lesson 6:** Kibana **Basic license** KHÔNG support `.webhook` connector cho detection rule actions — feature locked behind Gold tier. Khi tạo connector via API:
```
{"statusCode":403,"message":"Action type .webhook is disabled because your basic license does not support it."}
```

**Workaround:** systemd timer chạy mỗi 30s, poll ES alerts index, forward sang n8n webhook. Code: `soar/bridge/alert-forwarder.py`.

```bash
# Deploy
sudo cp soar/bridge/alert-forwarder.py /opt/vnsoc-soar/
sudo cp soar/bridge/vnsoc-soar.{service,timer} /etc/systemd/system/
sudo bash -c "cat > /etc/vnsoc-soar.env <<EOF
ES_URL=https://localhost:9200
ES_USER=elastic
ES_PASS=<ELASTIC_PASSWORD>
N8N_WEBHOOK=http://127.0.0.1:5678/webhook/kibana-alert
RULE_FILTER=[VN-SOC 
EOF"
sudo chmod 640 /etc/vnsoc-soar.env
sudo systemctl daemon-reload
sudo systemctl enable --now vnsoc-soar.timer
```

State file `/var/lib/vnsoc-soar/state.json` track last-seen `@timestamp` — restart-safe (Persistent=true).

### 3.8 Stage H — Smoke-test end-to-end

```bash
# Kali — trigger fresh attacks
for u in "/vulnerabilities/fi/?page=../../../../etc/shadow" "/.aws/credentials" \
         "/wp-config.php~" "/admin/.htpasswd"; do
  curl -s -o /dev/null "http://192.168.154.165:8080$u"
done

# Đợi ~60s: rule R6/R7/R8/R9 fire → alerts index → forwarder pick up
# Verify
sshpass -p '1' ssh gnid@192.168.154.165 'curl -s -X POST \
  "http://127.0.0.1:9000/api/v1/query?name=count" \
  -H "Authorization: Bearer <SOC_API_KEY>" \
  -H "Content-Type: application/json" \
  -d "{\"query\":[{\"_name\":\"listCase\"}]}"'
# → 34 cases total (33 từ replay + 1 fresh-attack case #34)
```

**Kết quả thực tế Pha 9:**

| Case # | Severity | Title | Source |
|---|---|---|---|
| 1-2 | MEDIUM | Direct test (manual) | curl trực tiếp TheHive |
| 3 | HIGH | webhook smoke v3 | Manual webhook POST |
| 4-33 | MEDIUM/HIGH | R6/R7/R8/R9 alerts từ replay | Forwarder replay last_ts backdate |
| 34 | MEDIUM | R6 Network Scan (fresh attack) | Forwarder picked up từ live ES |

---

## 4. Lessons learned (Pha 9) — gold cho CV interview

| # | Bài học | Stage | Detail |
|---|---|---|---|
| 1 | **n8n 1.x deprecated `N8N_BASIC_AUTH_*` env vars** — phải GUI setup owner wizard | B | env vars vẫn được parse nhưng không có tác dụng. User management built-in chiếm precedence. **Workaround:** chấp nhận GUI setup once + lưu credentials vào secrets vault. |
| 2 | **TheHive 5 docker args khác hoàn toàn TheHive 4** | C | Flags `--storage-type localfs` / `--storage-localfs-location` (v4) → KHÔNG TỒN TẠI trong v5. Đúng: `--storage-directory <path>`. Khi args sai → container restart loop in usage help. **Always verify với `docker logs <container> | head` khi container crash early.** |
| 3 | **Default admin `admin@thehive.local` không có manageCase permission** | D | TheHive 5 phân cấp: system admin (chỉ user/org mgmt), org admin/analyst (có case mgmt). Để dùng API tạo case → phải tạo org + user role analyst/org-admin riêng. |
| 4 | **SSH `-R` reverse tunnel default chỉ bind 127.0.0.1; Docker container ở custom bridge không reach được** | E | 3 thứ phải đồng thời: (1) `GatewayPorts yes` trên VPS sshd_config, (2) bind `-R "*:9000:..."`, (3) `network_mode: host` cho n8n container. Thiếu 1 → container timeout. **Diagnostic:** `docker exec <container> wget <target>` cho biết container có reach được không. |
| 5 | **n8n HTTP Request node typeVersion 4.2 default Method = GET** | F | Workflow JSON import KHÔNG có `"method": "POST"` → default GET → TheHive trả 404 (không phải 405) → misleading. **Always set method explicit** trong workflow JSON. Khi REST API trả 404 cho endpoint biết tồn tại → check HTTP method trước tiên. |
| 6 | **Kibana Basic license KHÔNG support `.webhook` connector** cho detection rule actions | G | 403 "Action type .webhook is disabled because your basic license does not support it." Workaround free-tier: poll ES alerts via systemd timer → bridge tới n8n webhook. Free-tier pattern này áp dụng cho hầu hết labs/SME — Gold license $$$. **Lesson cho cost-conscious SOC architecture.** |
| 7 | **Python f-string nested same-type quote vẫn fail trên Python 3.x mainline** (lặp lại từ Pha 7 Lesson 5) | Verify | Verification one-liner `print(f"x={d[\"key\"]}")` raise SyntaxError trên Python 3.10/3.11/3.13. Fix: dùng `.format()` hoặc single quote bên trong. **Đã 2 lần gặp trong project → cần memory này.** |

---

## 5. Files trong Pha 9

| File / Folder | Mô tả |
|---|---|
| `soar/n8n/docker-compose.yml` | n8n Docker (host network) |
| `soar/n8n/workflow-kibana-to-thehive.json` | Workflow JSON (3 nodes: webhook → function → http POST) |
| `soar/thehive/docker-compose.yml` | Cassandra + ES + TheHive 5 stack |
| `soar/bridge/alert-forwarder.py` | ES poll → n8n forward script |
| `soar/bridge/vnsoc-soar.service` | systemd oneshot service |
| `soar/bridge/vnsoc-soar.timer` | systemd timer every 30s |
| `pha9-results.md` | doc này |

---

## 6. Trạng thái Pha 9 cuối

| Hạng mục | Trạng thái |
|---|---|
| SOC-Tools VM RAM 4 GB | ✅ 2.9 GB free post-upgrade |
| Sysctl `vm.max_map_count=262144` | ✅ persist /etc/sysctl.d/99-thehive.conf |
| TheHive Cassandra | ✅ healthy, heap 512m |
| TheHive Elasticsearch | ✅ green, heap 512m |
| TheHive 5.4.0 | ✅ /api/status 200 |
| TheHive org "vn-soc-lab" + analyst user | ✅ |
| n8n 1.74.1 (network_mode: host) | ✅ port 5678 loopback |
| n8n workflow Kibana→TheHive | ✅ Active, webhook URL `/webhook/kibana-alert` |
| autossh reverse tunnel Kali→VPS:9000→SOC-Tools:9000 | ✅ stable |
| autossh local tunnel Kali←VPS:5678 (n8n GUI) | ✅ |
| systemd vnsoc-soar.timer | ✅ enabled, fires 30s |
| End-to-end smoke-test (fresh DVWA attack → TheHive case) | ✅ case #34 |
| Tổng TheHive cases sau Pha 9 | ✅ 34 (3 manual + 31 auto-forwarded) |

---

## 7. Pha 9 Quick stats

| Metric | Giá trị |
|---|---|
| Time setup infra (Stage A-C) | ~45 phút |
| Time debug TheHive args | ~15 phút |
| Time debug bootstrap auth/perm | ~20 phút |
| Time debug network bridging (3 layers: SSH, Docker net, GatewayPorts) | ~45 phút |
| Time debug n8n GET vs POST | ~30 phút |
| Time write bridge service + smoke-test | ~30 phút |
| TheHive RAM idle | ~1.3 GB / 2.7 GB heap budget |
| n8n RAM idle | ~130 MB / 500 MB limit |
| Forwarder service interval | 30s (Persistent=true, restart-safe) |
| Lessons learned mới Pha 9 | 7 (n8n auth deprecation, TheHive args, perms, SSH/Docker net, n8n GET default, Kibana license tier, f-string quirk repeat) |
| Tổng cases TheHive sau smoke-test | 34 |

---

## 8. Kiến trúc cuối lab (Pha 1 → 9)

```
                 KALI (attacker + analyst host)
                       │
                       ├─ trigger DVWA attack (curl + Atomic Red Team)
                       ├─ autossh reverse tunnels VPS↔SOC-Tools
                       └─ browse Kibana/n8n/TheHive UI via SSH local forwards
                       
                 Win10 endpoint (Winlogbeat → ES + Wazuh agent → Manager)
                 SOC-Tools VM (Suricata + DVWA + TheHive stack)
                 SOC-Wazuh VM (Wazuh Manager + Indexer + Dashboard)
                       │
                       ▼ (ship logs / metrics)
                 
                 VPS — central SIEM + SOAR plane:
                   ├─ Elastic stack (Pha 1): ES + Kibana + Logstash
                   │     index: winlogbeat-* | suricata-* | dvwa-apache-*
                   ├─ ML detection (Pha 8): Flask URL classifier :5000
                   ├─ SOAR bridge (Pha 9): poll alerts → n8n
                   └─ n8n (Pha 9): workflow → TheHive

Detection coverage (9 rules → MITRE):
  R1 T1059.001 PowerShell Encoded     | Execution
  R2 T1003.001 LSASS Memory Access    | Credential Access
  R3 T1547.001 Registry Run Key       | Persistence
  R4 T1110     Brute Force            | Credential Access
  R5 T1071.001 Non-Browser Outbound   | Command & Control
  R6 T1595     Network Scan           | Reconnaissance
  R7 T1595.002 Suspicious UA          | Reconnaissance
  R8 T1083     Sensitive File Probe   | Discovery
  R9 T1190     ML Malicious URL       | Initial Access
```

---

*Pha 9 hoàn tất. Lab end-to-end: Detection (Pha 3-8) → SOAR (Pha 9). Total 9 phases done. CV-ready.*
