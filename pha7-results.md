# Pha 7 — Wazuh Full Stack HIDS Results

> Multi-SIEM expansion: thêm Wazuh full stack (Manager + Indexer + Dashboard) trên VM local
> riêng, song song với Elastic SIEM hiện hữu trên VPS. Endpoint coverage được dual-stack
> (Winlogbeat → Elastic + Wazuh Agent → Wazuh Manager).

**Ngày thực hiện:** 2026-06-27
**Thời gian:** ~2.5 giờ (gồm 2 lần debug: RAM upgrade + disk expand)
**Hardware change:** +1 SOC-Wazuh VM local (Ubuntu 22.04, 4 GB RAM, 50 GB disk)

---

## 1. Tóm tắt

Pha 7 add **HIDS layer** vào lab — Wazuh 4.9.2 stack đầy đủ trên 1 VM mới, độc lập với Elastic stack ở VPS. Lý do chọn full stack thay vì chỉ Manager: muốn có **Wazuh Dashboard riêng** để so sánh UX với Kibana, đồng thời thực hành ops phía OpenSearch/Wazuh Indexer (fork OpenSearch + tuning heap).

- **Wazuh Manager + Indexer + Dashboard** chạy chung 1 Docker stack `single-node` (clone từ wazuh/wazuh-docker `v4.9.2`).
- **OpenSearch heap tune** xuống `-Xms1g -Xmx1g` (mặc định 1g/2g — quá lớn với VM 4 GB).
- **Wazuh Agent Windows MSI** install trên Win10 endpoint → enroll auto qua port 1515 → ship event qua 1514.
- **Verify end-to-end:** Manager API `/agents` trả về 2 agents (`wazuh.manager` self + `DESKTOP-L7FCMBQ` Win10), status `active`, lastKeepAlive cập nhật mỗi 10s, alerts.json populated với rule CIS Microsoft Windows 10 benchmark từ agent thực.

Pha 7 không tạo detection rule mới — focus pha này là **infrastructure stand-up** + **multi-stack pattern**. Rule custom cho Wazuh để dành Pha 9 (SOAR integration).

---

## 2. Architecture (sau Pha 7)

```
LOCAL VMware (NAT vmnet8 — 192.168.154.0/24):

  Kali              192.168.154.151   attacker / analyst
  Win10 victim      192.168.154.164   endpoint (Winlogbeat + Wazuh Agent)
  SOC-Tools VM      192.168.154.165   Suricata + DVWA (Pha 6)
  SOC-Wazuh VM      192.168.154.163   Wazuh full stack (Pha 7) ← NEW

  Ubuntu 22.04 — 2 vCPU, 4 GB RAM, 50 GB disk:
    Docker 29.6.1 + Compose v5.2.0
    Stack single-node-wazuh:
      - wazuh.manager   :1514 (agent data) :1515 (enrollment) :55000 (REST API)
      - wazuh.indexer   :9200 (OpenSearch HTTPS, self-signed)
      - wazuh.dashboard :443  (HTTPS UI, redirect from :5601)

VPS 43.228.215.234 (Elastic stack — unchanged Pha 1-6):
    Elasticsearch :9200, Kibana :5601, Logstash :5044, :5045
    Indices: winlogbeat-*, suricata-*, dvwa-apache-*

DUAL endpoint shipping từ Win10:
  Win10 → Winlogbeat   → VPS Logstash:5044 → ES (Sysmon/Security events)
  Win10 → Wazuh Agent  → SOC-Wazuh:1514    → Wazuh Manager (FIM/SCA/rootcheck)
```

**Lý do tách 2 stack thay vì ship Wazuh alerts vào Elastic (filebeat-wazuh module):**

- Bài học vận hành: thực hành standalone Wazuh stack (giống production team chạy 2 SIEM song song).
- Wazuh Dashboard expose riêng **MITRE module, SCA module, Vulnerability Detector module** mà Kibana base license không có.
- Optional future: pha 9 sẽ pipe Wazuh alerts → Logstash:5045 → ES → Kibana để unified view (đã list trong roadmap).

---

## 3. Setup stages

> **Dual-path convention:** Stage A (VM create) + Stage G (Wazuh Agent MSI install) + Stage H (verify Manager) có cả **GUI ưu tiên** + CLI. Stage B (sysctl) + Stage C (Docker install) + Stage D (Wazuh stack) + Stage F (disk expand `growpart`) là **CLI-only** — Linux sysadmin không có GUI standard cho những tác vụ này.

### 3.1 Stage A — Tạo VM SOC-Wazuh (VMware Workstation GUI)

**GUI (ưu tiên):**
1. VMware → **File → New Virtual Machine → Typical**.
2. **Installer disc image (ISO)** → chọn `ubuntu-22.04.x-live-server-amd64.iso`.
3. Easy Install: name `gnid`, password `1`, hostname `soc-wazuh`.
4. VM name `SOC-Wazuh`, location mặc định.
5. **Maximum disk size: 50 GB**, **Store virtual disk as a single file**.
6. **Customize Hardware** → Memory **4096 MB**, Processors 2, Network Adapter **NAT (vmnet8)**.
7. Finish → boot → Ubuntu autoinstall.

**CLI alternative (nếu dùng `vmrun`):**
```bash
# Trên Win host, dùng VMware Workstation Pro CLI tools
vmrun -T ws createVM -name SOC-Wazuh -mem 4096 -hwversion 19 \
  -ostype ubuntu-64 -disk-size 50GB ...
# Trên thực tế GUI nhanh hơn vì cần chỉnh nhiều params; CLI chủ yếu cho automation/CI.
```

Sau install hoàn tất, từ Kali:
```bash
ssh gnid@192.168.154.163        # password: 1
ip a | grep 192.168.154         # confirm IP
```

> ⚠️ **Lesson 1 (Pha 7):** Lần đầu mình tạo VM với **2 GB RAM** — boot lên Wazuh stack rồi Indexer OOM-kill trong ~30s. Phải power off, sửa Memory lên 4096 MB, boot lại. **Wazuh full stack tối thiểu thực tế là 4 GB RAM** (không phải 2 GB như docs Wazuh nói cho "minimal").

### 3.2 Stage B — Sysctl tuning cho OpenSearch (CLI-only — không có GUI)

OpenSearch (Wazuh Indexer fork) cần `vm.max_map_count >= 262144` để allocate memory-mapped files cho Lucene segments. Mặc định Ubuntu là 65530 → start lên crash với `max virtual memory areas vm.max_map_count is too low`.

```bash
# Permanent tuning
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-wazuh.conf
sudo sysctl --system | grep max_map_count
# → vm.max_map_count = 262144
```

> CLI-only — VMware/Ubuntu không expose sysctl qua bất kỳ GUI nào.

### 3.3 Stage C — Cài Docker 29 + Compose v5

**CLI (chuẩn, dual-path GUI không tồn tại trên Ubuntu Server):**
```bash
# Add Docker repo (bash -c để workaround pipe broken — xem Pha 6 Lesson 2)
sudo bash -c "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && chmod a+r /etc/apt/keyrings/docker.gpg"

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
# Logout + login lại
docker --version            # → Docker version 29.6.1
docker compose version      # → Docker Compose version v5.2.0
```

### 3.4 Stage D — Clone wazuh-docker single-node + tune heap

```bash
mkdir -p ~/soc-wazuh && cd ~/soc-wazuh
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.2
cd wazuh-docker/single-node
```

**Generate SSL certs** (Wazuh stack 100% TLS, không có HTTP plain):
```bash
docker compose -f generate-indexer-certs.yml run --rm generator
ls config/wazuh_indexer_ssl_certs/
# → admin-key.pem  admin.pem  root-ca.key  root-ca.pem  wazuh.indexer-key.pem ...
```

**Patch heap tuning** (xem `configs/wazuh-docker-compose.yml` — diff so với upstream):

```yaml
# Trong service wazuh.indexer.environment, thêm:
- "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
```

Mặc định OpenSearch alloc `-Xms2g -Xmx2g` → trên VM 4 GB sẽ OOM khi Manager + Dashboard cùng start.

### 3.5 Stage E — Boot stack + verify

```bash
docker compose up -d
# Đợi ~90s cho Indexer election + Dashboard handshake
docker compose ps
```

**Output mong đợi:**
```
NAME                          STATUS
single-node-wazuh.dashboard-1 Up
single-node-wazuh.indexer-1   Up
single-node-wazuh.manager-1   Up
```

**Verify Indexer health (CLI):**
```bash
curl -sk -u admin:SecretPassword https://localhost:9200/_cluster/health | jq .
# → {"status":"green","number_of_nodes":1,"active_primary_shards":10,...}
```

**Verify Dashboard (GUI):**
1. Trên Kali browser: `https://192.168.154.163` (port 443).
2. Self-signed warning → Advanced → Proceed.
3. Login `admin` / `SecretPassword` (lab default — đã ghi hardening backlog).
4. Wazuh menu → **Agents** → list trống (chưa enroll agent nào).

> ⚠️ **Lesson 2 (Pha 7):** Lần boot đầu Indexer log `cluster_manager_not_discovered_exception` → debug ~20 phút mới ra: disk full 100% (Wazuh ate 14 GB cho containerd image + queue). Xem Lesson 3 dưới.

### 3.6 Stage F — Disk expand 20 → 50 GB (online, không reboot)

Triệu chứng: `docker compose up` chạy 1 lần OK, ngày hôm sau Indexer crash, `df -h /` báo 100%.

```bash
# Trên VMware GUI: VM Settings → Hard Disk → Expand → 50 GB
# (Không có CLI cho operation này vì là VMware hypervisor-side)

# Trên VM (online resize, không reboot):
sudo growpart /dev/sda 2
sudo resize2fs /dev/sda2
df -h /
# → /dev/sda2  50G  25G  23G  52% /
```

Lý do KHÔNG cần `lvextend` như Pha 6: Ubuntu installer Pha 7 mình chọn **"Use entire disk"** không tick LVM → mount trực tiếp `/dev/sda2`, không có VG layer giữa.

> ⚠️ **Lesson 3 (Pha 7):** Wazuh full stack chiếm **~14 GB** disk ngay sau boot (Docker images Manager + Indexer ~5 GB + containerd metadata ~3 GB + Manager queue baseline 1.3 GB + Indexer data + OpenSearch segments growing). **20 GB disk là không đủ** — minimum thực tế 40 GB, comfortable 50 GB.

### 3.7 Stage G — Cài Wazuh Agent trên Win10 endpoint

**GUI (ưu tiên — Wazuh Dashboard tự generate command):**
1. Trên Wazuh Dashboard → **Agents → Deploy new agent**.
2. Chọn OS: Windows.
3. Server address: `192.168.154.163`.
4. Agent name: để trống (auto dùng hostname).
5. Copy block PowerShell command Dashboard sinh sẵn.
6. Trên Win10, **PowerShell as Administrator**:
   ```powershell
   Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi `
     -OutFile $env:tmp\wazuh-agent
   msiexec.exe /i $env:tmp\wazuh-agent /q `
     WAZUH_MANAGER='192.168.154.163' `
     WAZUH_AGENT_NAME='DESKTOP-L7FCMBQ'
   NET START WazuhSvc
   ```

**CLI alternative (full PowerShell, không cần Dashboard):**
```powershell
# Identical to GUI-generated command above — chỉ là copy/paste manual
```

**Verify từ Win10:**
```powershell
Get-Service WazuhSvc                                    # → Running
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 10
# → "Connected to server 192.168.154.163/1514"
# → "Valid key received"
```

> ⚠️ **Lesson 4 (Pha 7):** Lần đầu agent install xong nhưng Manager API báo `total_affected_items: 0` — không có agent nào enroll. **Root cause chính xác (qua `ossec.log` chẩn đoán):** MSI install kích hoạt `WazuhSvc` TRƯỚC khi `agent-auth.exe` kịp xin key. Service chạy với `client.keys` trống → bật auto-enrollment loop. Trong khi đó `agent-auth.exe` đăng ký thành công tên hostname với Manager + ghi `client.keys` mới. Service vẫn chạy loop cũ, không reload key file → gửi yêu cầu enroll tên `DESKTOP-L7FCMBQ` LẦN 2 lên Manager → Manager refuse với lỗi lặp:
> ```
> ERROR: Duplicate agent name: DESKTOP-L7FCMBQ (from manager)
> ERROR: Unable to add agent (from manager)
> ```
> **Fix robust 2 bước:** (1) `agent-auth.exe -m 192.168.154.163 -A $env:COMPUTERNAME` để force enrollment, (2) `Restart-Service WazuhSvc` để reload key file. KHÔNG dựa vào auto-enrollment MSI vì race condition này.

### 3.8 Stage H — Verify end-to-end (từ Manager)

**GUI (Wazuh Dashboard):**
1. Browser `https://192.168.154.163` → login admin.
2. **Wazuh → Agents** → thấy `DESKTOP-L7FCMBQ` status **active**.
3. Click vào agent → **Security events / Integrity monitoring / SCA** đều có data.

**CLI (Wazuh Manager API):**
```bash
# Auth → token (5 phút TTL)
TOKEN=$(curl -sk -u "wazuh-wui:MyS3cr37P450r.*-" \
  -X POST "https://localhost:55000/security/user/authenticate" \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['token'])")

# List agents
curl -sk -X GET "https://localhost:55000/agents" \
  -H "Authorization: Bearer $TOKEN" | jq '.data.affected_items[]
    | {id, name, ip, status, lastKeepAlive}'
```

**Output thực tế Pha 7 (2026-06-27 05:12):**
```json
{
  "id": "000",
  "name": "wazuh.manager",
  "ip": "127.0.0.1",
  "status": "active"
}
{
  "id": "001",
  "name": "DESKTOP-L7FCMBQ",
  "ip": "192.168.154.164",
  "status": "active",
  "lastKeepAlive": "2026-06-27T05:12:17+00:00"
}
```

**Tail alerts từ agent thực (không phải self):**
```bash
docker exec single-node-wazuh.manager-1 tail -50 /var/ossec/logs/alerts/alerts.json \
  | jq 'select(.agent.name != "wazuh.manager")
    | {ts: .timestamp, agent: .agent.name, lvl: .rule.level,
       rule: .rule.id, desc: .rule.description}'
```

→ Thấy 5+ alerts CIS Microsoft Windows 10 Enterprise Benchmark từ agent — confirm end-to-end pipeline OK.

---

## 4. Lessons learned (Pha 7)

| # | Bài học | Stage | Detail |
|---|---|---|---|
| 1 | Wazuh full stack RAM minimum thực tế là 4 GB | A | 2 GB → Indexer OOM-kill ~30s sau boot. Docs Wazuh ghi "minimal 2 GB" chỉ đủ cho Manager standalone, không phải full stack 3 services. Khi sizing VM cho production-like lab: alloc theo số services × 1.5 GB heap headroom. |
| 2 | Single-disk Ubuntu install không LVM = không cần `lvextend` Pha 6 | F | Pha 6 dùng "Use entire disk + setup LVM" (default Ubuntu installer) → VG/LV layer. Pha 7 chọn "Use entire disk" KHÔNG tick LVM → direct partition. Online resize chỉ cần `growpart` + `resize2fs`, đơn giản hơn. **Bài học sizing: chọn LVM khi muốn flexibility extend nhiều lần; chọn non-LVM khi muốn troubleshoot đơn giản.** |
| 3 | Wazuh full stack chiếm 14 GB disk baseline | E,F | 20 GB là KHÔNG đủ. Comfortable 50 GB. Cụ thể: containerd 13 GB (images + overlay layers) + Manager queue 1.3 GB initial. Khi disk full, Indexer fail state-file write → cluster_manager election fail → cả stack down im lặng. |
| 4 | Wazuh Agent MSI install có thể fail enrollment im lặng | G | MSI khởi động service trước khi `WAZUH_MANAGER` env var được commit vào ossec.conf đúng cách. Fix robust: sau install, luôn chạy `agent-auth.exe -m <manager>` thủ công + restart service, KHÔNG dựa vào auto-enrollment MSI. |
| 5 | Python f-string KHÔNG cho phép nested same-type quote trong Python <3.12 | Verify | `f"x={a.get("id")}"` raises `SyntaxError: f-string: unmatched '('` trên Python 3.10 (Ubuntu 22.04 default). Fix: dùng single quote bên trong `f"x={a.get('id')}"`, hoặc `.format()`. Quirk này xuất hiện khi viết verification one-liner phức tạp qua SSH. |

---

## 5. Files trong Pha 7

| File | Mô tả |
|---|---|
| `configs/wazuh-docker-compose.yml` | docker-compose.yml hoàn chỉnh đã patch heap tune (snapshot từ SOC-Wazuh VM) |
| `pha7-results.md` | doc này |

Không thêm detection-rule mới — Wazuh dùng ruleset built-in (OOTB) trong Pha 7.

---

## 6. Trạng thái Pha 7 cuối

| Hạng mục | Trạng thái |
|---|---|
| SOC-Wazuh VM tạo + boot + SSH | ✅ 192.168.154.163, Ubuntu 22.04 |
| RAM 4 GB (sau khi upgrade từ 2) | ✅ |
| Disk 50 GB (sau khi expand từ 20) | ✅ 52% used post-stack |
| sysctl `vm.max_map_count=262144` | ✅ persist via `/etc/sysctl.d/99-wazuh.conf` |
| Docker 29 + Compose v5 | ✅ 29.6.1 / v5.2.0 |
| Wazuh stack 3 containers | ✅ Manager + Indexer + Dashboard all `Up` |
| OpenSearch heap tune `-Xms1g -Xmx1g` | ✅ |
| Indexer cluster health | ✅ green, 10 active primary shards |
| Wazuh Dashboard HTTPS:443 | ✅ login OK |
| Wazuh Manager REST API:55000 | ✅ auth + agent list OK |
| Wazuh Agent Win10 (DESKTOP-L7FCMBQ) | ✅ `active`, lastKeepAlive realtime |
| alerts.json populated từ agent | ✅ 5+ CIS Windows benchmark alerts |
| Multi-SIEM coexistence (Elastic + Wazuh) | ✅ Win10 ship 2 đầu song song |

---

## 7. Pha 7 Quick stats

| Metric | Giá trị |
|---|---|
| Time setup infrastructure (Stage A→F) | ~1.5 giờ |
| Time debug RAM + disk full + enrollment | ~1 giờ |
| Disk usage sau boot | 25 GB / 50 GB (50%) |
| RAM usage sau boot | 2.0 GB / 4.0 GB (idle) |
| Stack containers running | 3 (Manager + Indexer + Dashboard) |
| Wazuh agents registered | 2 (`000` self + `001` Win10 endpoint) |
| Lessons learned mới Pha 7 | 5 (RAM sizing, LVM vs non-LVM, disk sizing, MSI enrollment, Python f-string quirk) |

---

*Pha 7 hoàn tất end-to-end. Multi-SIEM stack hoạt động song song. Sẵn sàng Pha 8 — AI/ML detection (Flask API trên VPS).*
