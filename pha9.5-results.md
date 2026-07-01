# Pha 9.5 — Cortex Analyzer Integration (TheHive auto-enrich)

> Mở rộng Pha 9 SOAR: gắn **Cortex 3** vào TheHive 5 để auto-enrich observables.
> Analyst trong TheHive click 1 nút → Cortex chạy VirusTotal / AbuseIPDB analyzer →
> kết quả attach vào case. Khâu cuối còn thiếu để SOC ops loop khép kín.

**Ngày thực hiện:** 2026-06-27
**Thời gian:** ~1.5 giờ (gồm debug 3 lần: ES mem_limit, CSRF auth, Docker job_directory bind)
**Hardware change:** +2 Docker containers (Cortex 3.1.7 + ES 7) trên SOC-Wazuh VM

---

## 1. Tóm tắt

Pha 9 đã có **detect → ES → bridge → n8n → TheHive case auto**. Còn thiếu một mảnh: **auto-enrich observables**. Pha 9.5 thêm:

- **Cortex 3.1.7** standalone trên SOC-Wazuh VM (cùng host Wazuh stack, tận dụng RAM headroom).
- **2 analyzers free-tier:** VirusTotal_GetReport + AbuseIPDB.
- **TheHive 5 ↔ Cortex integration:** TheHive analyst gọi analyzer từ case observable → Cortex spawn Docker analyzer image → report attach về TheHive.
- **Verify end-to-end:** observable `185.220.101.1` (Tor exit IP) → AbuseIPDB analyzer → report đầy đủ (abuse score 100, hostname `berlin01.tor-exit.artikel10.org`, 56 reports, isTor=true) attach vào case #40.

---

## 2. Architecture delta vs Pha 9

```
                                            ┌────────────────────────────────┐
                                            │  SOC-Wazuh VM (192.168.154.163)│
                                            │  ├─ Wazuh stack (Pha 7)        │
                                            │  ├─ Cortex 3.1.7 :9001 (NEW)   │
                                            │  └─ cortex-es 7.17 :9200       │
                                            └────────────────┬───────────────┘
                                                             │ HTTP REST + Bearer key
                                                             │ (LAN 192.168.154.x)
                                                             ▼
        Kali analyst ───── browser ──── TheHive 5 :9000 ──── Cortex 0 (cortex0)
                                            │                       │
                                            │  configured via       │ docker spawn
                                            │  --cortex-hostnames   │
                                            │  --cortex-port        ▼
                                            │  --cortex-keys        ┌──────────────────┐
                                            │                       │ analyzer container│
                                            │ ◄─── report.json ─────│  AbuseIPDB v2    │
                                            ▼                       │  or VirusTotal v3│
                              TheHive case observable enriched      └──────────────────┘
                              (attach report.full + summary.taxonomies)
```

---

## 3. Setup stages

> **Dual-path convention:** Stage A (resource check) + Stage B (Docker deploy) + Stage F (TheHive Cortex wire) là **CLI-only** (service config file/systemd). Stage C (bootstrap) + Stage D (enable analyzers) + Stage G (smoke-test) có **GUI ưu tiên** (Cortex 3 CSRF strict, GUI đường tắt) — CLI chỉ khả thi tới bước tạo superadmin đầu tiên. Stage E (analyzer test) qua Bearer API key CLI hoặc GUI Cortex "Run Analyzer" button.

### 3.1 Stage A — Tài nguyên check trước deploy

```bash
sshpass -p '1' ssh gnid@192.168.154.163 'free -h | head -2'
# → 1.5 GB available — đủ cho Cortex stack (~800 MB)
```

> ⚠️ **Lesson 1:** SOC-Tools đã max RAM (TheHive stack chiếm 2.5 GB / 3.8 GB, free 324 MB) → không host được Cortex. Chọn SOC-Wazuh vì có 1.5 GB free + cùng network 192.168.154.0/24 với SOC-Tools → không cần SSH tunnel cross-network như Pha 9.

### 3.2 Stage B — Deploy Cortex 3 + ES 7 (Docker compose)

**CLI:**
```bash
cd ~/soar/cortex
PLAY_SECRET=$(openssl rand -base64 32 | tr -d '/+=' | head -c 40)
sed -i "s|\${PLAY_SECRET}|$PLAY_SECRET|" application.conf
docker compose up -d
```

File `soar/cortex/docker-compose.yml` quan trọng:

```yaml
cortex-elasticsearch:
  image: docker.elastic.co/elasticsearch/elasticsearch:7.17.27
  environment: [ ES_JAVA_OPTS=-Xms384m -Xmx384m, bootstrap.memory_lock=true ]
  mem_limit: 900m   # ⚠️ Lesson 2 — 600m không đủ, ES thrashing 107% CPU

cortex:
  image: thehiveproject/cortex:3.1.7
  ports: ["0.0.0.0:9001:9001"]
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock   # spawn analyzer containers
    - /tmp/cortex-jobs:/tmp/cortex-jobs           # ⚠️ Lesson 3 — bind mount, KHÔNG named volume
    - ./application.conf:/etc/cortex/application.conf:ro
  mem_limit: 600m
```

> ⚠️ **Lesson 2 (Pha 9.5):** Lần đầu set ES `mem_limit: 600m` (cùng heap 384m). ES container chạm cứng 600 MB, CPU thrashing 107%, không response query — Cortex báo `NoNodeAvailable / ElasticSearch cluster is unreachable` dù healthcheck pass. Fix: bump `mem_limit: 900m` (heap 384m + overhead JVM ~500 MB).

> ⚠️ **Lesson 3 (Pha 9.5):** Cortex 3 dùng Docker socket spawn analyzer container (sibling docker). Job dir cần **bind mount từ host path** (`/tmp/cortex-jobs:/tmp/cortex-jobs`), KHÔNG named volume (`cortex_jobs:/tmp/cortex-jobs`). Lý do: khi Cortex tell host docker daemon "spawn analyzer container with mount /tmp/cortex-jobs", host docker daemon biết path `/tmp/cortex-jobs` trên HOST filesystem, không biết named volume internals của Cortex container. Triệu chứng nếu sai: analyzer crash với `json.load(sys.stdin)` empty input.

### 3.3 Stage C — Bootstrap superadmin + org + analyst user

**GUI (ưu tiên — vì Cortex 3 CSRF strict cho mọi non-GET API call sau login):**
1. Browser → `http://192.168.154.163:9001/`
2. First-run wizard: tạo superadmin `admin` + password.
3. **Organisations → Add new** → name `vn-soc-lab`, status Active.
4. **Users → Add new** (org `vn-soc-lab`): login `soc@vn-soc-lab.local`, roles tick `read` + `analyze` + `orgAdmin`. Set password.
5. Login lại dưới user `soc` → Profile → **API key → Create/Renew** → copy key.

**CLI (chỉ partial-feasible vì CSRF):**
```bash
# Initial superadmin creation (no auth needed)
curl -s -X POST http://127.0.0.1:9001/api/maintenance/migrate -d '{}'
curl -s -X POST http://127.0.0.1:9001/api/user \
  -H "Content-Type: application/json" \
  -d '{"login":"admin","name":"Super Admin","roles":["superadmin"]}'
# Subsequent calls (create org, user, key) → ALL require CSRF → use GUI.
```

> ⚠️ **Lesson 4 (Pha 9.5):** Cortex 3 áp dụng **CSRF protection nghiêm ngặt** lên mọi POST/PUT/DELETE sau khi đã có session cookie. Bypass header `X-Requested-With: XMLHttpRequest` không work; basic auth không work; JWT từ cookie cũng không. Bootstrap khả thi qua API chỉ tới bước tạo first superadmin. **Mọi bước sau bắt buộc GUI** (cho lab) hoặc viết Selenium script (production CI). Cortex 3 docs hiếm khi đề cập rõ — debug mất ~15 phút.

### 3.4 Stage D — Enable analyzers + config API key

**GUI:**
1. Login user `soc@vn-soc-lab.local`.
2. **Organisation → Analyzers → "+ Refresh Analyzers"** (download danh sách 275 analyzers từ thehive-project.org).
3. Filter `VirusTotal_GetReport` → Enable → config form:
   - `key`: VirusTotal API key (free-tier, từ virustotal.com/api).
4. Filter `AbuseIPDB` → Enable → config:
   - `key`: AbuseIPDB API key (free-tier, từ abuseipdb.com/api).

**CLI (API key auth — sau khi đã có user key qua GUI):**
```bash
SOC_KEY="<CORTEX_SOC_API_KEY>"
curl -s -H "Authorization: Bearer $SOC_KEY" -X POST \
  "http://192.168.154.163:9001/api/organization/analyzer/VirusTotal_GetReport_3_1" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"VirusTotal_GetReport_3_1",
    "configuration":{"key":"<VT_API_KEY>","polling_interval":60,"check_tlp":true,"max_tlp":2,"check_pap":true,"max_pap":2},
    "jobCache":10
  }'

curl -s -H "Authorization: Bearer $SOC_KEY" -X POST \
  "http://192.168.154.163:9001/api/organization/analyzer/AbuseIPDB_2_0" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"AbuseIPDB_2_0",
    "configuration":{"key":"<AB_API_KEY>","days":30,"check_tlp":true,"max_tlp":2,"check_pap":true,"max_pap":2},
    "jobCache":10
  }'
```

### 3.5 Stage E — Smoke-test analyzer standalone

```bash
SOC_KEY="<CORTEX_SOC_API_KEY>"
JOB=$(curl -s -H "Authorization: Bearer $SOC_KEY" -X POST \
  "http://192.168.154.163:9001/api/analyzer/<abuseIpdbId>/run" \
  -H "Content-Type: application/json" \
  -d '{"data":"185.220.101.1","dataType":"ip","tlp":2,"pap":2}')
```

Kết quả (sau ~15s):
```json
{
  "summary": { "taxonomies": [
    { "level": "malicious", "namespace": "AbuseIPDB", "predicate": "Score", "value": 100 },
    { "level": "malicious", "namespace": "AbuseIPDB", "predicate": "Reports", "value": 56 },
    { "level": "info", "namespace": "AbuseIPDB", "predicate": "Tor", "value": "True" }
  ]}
}
```

### 3.6 Stage F — Wire TheHive ↔ Cortex

Edit `soar/thehive/docker-compose.yml` command args:

```yaml
command:
  - "--secret"
  - "${THEHIVE_SECRET}"
  - "--cql-hostnames"
  - "cassandra"
  - "--index-backend"
  - "elasticsearch"
  - "--es-hostnames"
  - "elasticsearch"
  - "--storage-directory"
  - "/data/files"
  # Cortex integration (replace previous --no-config-cortex)
  - "--cortex-hostnames"
  - "192.168.154.163"
  - "--cortex-port"
  - "9001"
  - "--cortex-proto"
  - "http"
  - "--cortex-keys"
  - "${CORTEX_KEY}"
```

Apply:
```bash
echo 'CORTEX_KEY=<SOC_API_KEY>' >> .env
docker compose up -d --force-recreate thehive
```

Verify từ TheHive:
```bash
curl -s -H "Authorization: Bearer <THEHIVE_KEY>" \
  http://192.168.154.165:9000/api/connector/cortex/analyzer
# → 2 analyzers AbuseIPDB_2_0, VirusTotal_GetReport_3_1 với cortexIds=["cortex0"]
```

### 3.7 Stage G — End-to-end smoke-test qua TheHive UI

**GUI (ưu tiên):**
1. Browser → `http://192.168.154.165:9000/` (TheHive).
2. Mở case mới nhất (#40 — `[VN-SOC R9] ML Malicious URL Detection`).
3. Tab **Observables → Add → IP** → data `185.220.101.1`, TLP Amber, message "Pha 9.5 smoke-test (Tor exit)".
4. Click observable → tab **Analyzers** → tick `AbuseIPDB_2_0` → **Run** button.
5. Đợi ~15s → refresh → tab Reports thấy taxonomies + full report attached.

**CLI alternative:**
```bash
TH_KEY="<THEHIVE_SOC_API_KEY>"
CASEID="~8056888"   # case #40

# Add observable (v0 artifact path — v1 observable path báo 403 imperm)
curl -s -X POST "http://192.168.154.165:9000/api/case/$CASEID/artifact" \
  -H "Authorization: Bearer $TH_KEY" \
  -H "Content-Type: application/json" \
  -d '{"dataType":"ip","data":"185.220.101.1","message":"smoke","tlp":2}'

# Run analyzer
curl -s -X POST "http://192.168.154.165:9000/api/connector/cortex/job" \
  -H "Authorization: Bearer $TH_KEY" \
  -H "Content-Type: application/json" \
  -d '{"analyzerId":"AbuseIPDB_2_0","cortexId":"cortex0","artifactId":"<obs_id>"}'
```

> ⚠️ **Lesson 5 (Pha 9.5):** TheHive 5 dùng `/api/v1/case/{id}/observable` cho v1 API nhưng trả 403 "Operation not permitted" với user `org-admin`. Fallback path `/api/case/{id}/artifact` (v0 prefix) hoạt động — TheHive 5 giữ backward-compat các path v0 cho 1 số endpoint. Khi v1 fail 403 và bạn KNOW user có permission, thử v0 path trước khi debug RBAC.

---

## 4. Lessons learned (Pha 9.5)

| # | Bài học | Stage | Detail |
|---|---|---|---|
| 1 | Cortex 3 ES container `mem_limit` 600m → thrashing | B | Heap 384m + JVM overhead ~500 MB; cần limit ≥ 900m để có headroom. Triệu chứng: ES healthcheck pass nhưng query fail `NoNodeAvailable`. |
| 2 | Cortex 3 job_directory phải bind mount HOST path | B | Cortex spawn analyzer container via Docker socket; host docker daemon mount theo HOST filesystem path. Named volume → analyzer crashes vì stdin empty. |
| 3 | Cortex 3 CSRF protection strict | C | Sau login, mọi POST/PUT/DELETE require CSRF token. Browser GUI workflow là path-of-least-resistance cho bootstrap. CLI chỉ khả thi tới initial superadmin creation. |
| 4 | TheHive 5 ↔ Cortex config 100% qua container args | F | Không có /api/admin/cortex runtime endpoint. Phải `--cortex-hostnames/port/proto/keys` trong docker-compose command, restart container. |
| 5 | TheHive 5 path `/api/v1/case/.../observable` báo 403 — fallback v0 `/api/case/.../artifact` work | G | Backward-compat path. Khi v1 perm fail thử v0 trước khi debug RBAC. |

---

## 5. Files trong Pha 9.5

| File | Mô tả |
|---|---|
| `soar/cortex/docker-compose.yml` | Cortex 3 + ES 7 stack (heap 384m, mem_limit 900m ES) |
| `soar/cortex/application.conf` | Search ES URI, analyzer URLs, auth local provider |
| `soar/thehive/docker-compose.yml` | Updated command args wiring Cortex |
| `pha9.5-results.md` | doc này |

---

## 6. Trạng thái Pha 9.5 cuối

| Hạng mục | Trạng thái |
|---|---|
| Cortex 3.1.7 stack trên SOC-Wazuh | ✅ Up, healthcheck OK |
| Cortex superadmin + org + analyst user | ✅ via GUI |
| VirusTotal_GetReport analyzer enabled | ✅ free-tier key |
| AbuseIPDB analyzer enabled | ✅ free-tier key |
| Standalone analyzer smoke-test | ✅ AbuseIPDB → score 100 trên Tor IP |
| TheHive ↔ Cortex config | ✅ 2 analyzers visible với cortexIds=["cortex0"] |
| TheHive → Cortex job run end-to-end | ✅ case #40 observable enriched (Tor exit, Germany, abuse 100) |
| RAM SOC-Wazuh sau deploy | ~700 MB free / 3.8 GB total |

---

## 7. Pha 9.5 Quick stats

| Metric | Giá trị |
|---|---|
| Time setup (Stage A→G) | ~1 giờ |
| Time debug ES mem + CSRF + job_directory | ~30 phút |
| Cortex analyzers enabled | 2 (mở rộng dễ qua GUI, 273 available) |
| RAM Cortex stack idle | 600 MB (ES) + 400 MB (Cortex) = 1.0 GB |
| Lessons learned | 5 (ES mem_limit, bind mount, CSRF, container args config, v0 fallback) |
| Analyzer providers free-tier | VirusTotal (500/day), AbuseIPDB (1000/day) — đủ lab |

---

*Pha 9.5 hoàn tất. SOC ops loop khép kín: detect → case → enrich → investigate → respond.*
