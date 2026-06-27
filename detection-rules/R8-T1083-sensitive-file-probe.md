# R8 — Sensitive File / Path Probe (Web)

| Thuộc tính | Giá trị |
|---|---|
| Rule ID | `vnsoc-r8-sensitive-file-probe` |
| MITRE Tactic | TA0007 — Discovery |
| MITRE Technique | **T1083** File and Directory Discovery |
| Severity | **Medium** |
| Risk score | 47 |
| Index pattern | `dvwa-apache-*` |
| Rule type | Custom query (KQL) |
| Schedule | Every 1 minute, look-back 5 minutes (lab cycle nhanh) |
| Status | ✅ Deployed + verified 2026-06-27 (10 alerts trong 5 phút smoke-test) |

## 1. Vì sao detect cái này

Attacker sau khi discover web service sẽ probe các **sensitive path** common:

- **Config / credential files**: `.env`, `.git/config`, `wp-config.php`, `config.php`
- **Admin panels**: `/admin`, `/phpmyadmin`, `/wp-admin`, `/manager/html` (Tomcat)
- **Backup files**: `*.bak`, `*.old`, `*.zip`, `backup.sql`
- **System files**: `/etc/passwd` (LFI), `/proc/self/environ`
- **PHP shells**: `c99.php`, `r57.php`, `webshell.php`

Mỗi probe là **1 HTTP GET** đến path cụ thể. Nếu response 200 → attacker thấy file tồn tại → exploit phase. Detect probe sớm = block attacker IP trước khi họ kiếm được path nhạy cảm.

T1083 File and Directory Discovery cover cả on-host và network-layer discovery.

## 2. KQL query (final — đã verify)

```
url.original.keyword: (
  *.env* OR
  *.git* OR
  *wp-config* OR
  *config.php* OR
  *admin* OR
  *phpmyadmin* OR
  *wp-admin* OR
  *manager/html* OR
  *backup* OR
  *passwd* OR
  *.bak* OR
  *.old* OR
  *webshell* OR
  *c99.php* OR
  *r57.php*
)
```

**Giải thích — 3 KQL bug đã debug trong Pha 6 (xem §2a):**

- Field `url.original` thay cho `request` — Logstash 8.x ECS v8 mode auto-convert grok output sang ECS field structure. `request` → `url.original`, `clientip` → `source.address`, `verb` → `http.request.method`, etc.
- Sub-field `.keyword` bắt buộc — `url.original` là text field bị tokenize làm mất `.` và `/` (vd `/.env` → token `env`). Wildcard `*.env*` không match token `env`. Phải dùng `url.original.keyword` (full-string raw).
- KHÔNG dùng `\.` escape — `.` không phải special char trong KQL. `\.` invalid escape → parse fail.
- Tránh sequence `/*` — trong Lucene query parser `/*` mở comment, làm fail toàn query. Đổi `*.git/*` thành `*.git*`.

### 2a. Bài học KQL bugs Pha 6

<a id="2a-bài-học-kql-bugs-pha-6"></a>

Trong Pha 6 đã gặp **5 KQL bugs** liên quan ECS field convert + KQL parser:

| # | Bug | Triệu chứng | Fix |
|---|---|---|---|
| 1 | Logstash 8.x ECS v8 mode tự rename grok fields | Field `agent`, `request`, `clientip` không tồn tại như spec | Dùng ECS path: `user_agent.original`, `url.original`, `source.address`, `http.request.method`, `http.response.status_code` |
| 2 | Filebeat metadata overwrite root `agent` field | `agent: *sqlmap*` match Filebeat metadata, KHÔNG match HTTP UA | Dùng `user_agent.original` thay vì `agent` |
| 3 | Text field tokenize làm wildcard miss separator | `*.env*` 0 match dù `/.env` exist (tokenize → `env`) | Dùng `.keyword` sub-field cho path-like strings |
| 4 | Quote quanh wildcard biến thành literal | `"*sqlmap*"` match literal `*sqlmap*` (có asterisk thật), 0 hit | Bỏ quotes — KQL `*sqlmap*` (no quote) = wildcard |
| 5 | `/*` parse là Lucene comment-open | Toàn query fail với EOF parse error | Tránh sequence `/*` — viết `*git*` thay vì `*.git/*` |

**Bài học lớn:** Trước khi viết KQL detection rule, **luôn query 1 sample doc** trong Discover → check field path thực tế trong `_source`. Đừng tin spec viết sẵn (đặc biệt khi spec dựa trên Logstash 7.x hoặc grok plain output).

```bash
# Verify field path từ VPS trước khi viết KQL:
curl -sk -u "elastic:$PW" "https://<ES>:9200/<index>/_search?size=1&pretty"
```

Áp dụng cho R6/R7/R8: R6 OK (Suricata native ECS), R7+R8 fail 2 vòng debug ECS field → keyword fix.

## 3. Ví dụ event match (đã observed Pha 6)

```yaml
@timestamp : 2026-06-26T04:06:43Z
clientip   : 192.168.154.151
verb       : GET
request    : /.env
response   : 404                            ← file không tồn tại, nhưng probe đã ghi
agent      : curl/8.19.0
```

→ Match. Suricata cũng fire `ET INFO Request to Hidden Environment File - Inbound` — 2 layer detection cùng 1 event.

## 4. False-positive thường gặp & cách lọc

| FP scenario | Đặc trưng | Khuyến nghị |
|---|---|---|
| Crawler bot (Googlebot, Bingbot) auto-probe | UA chứa "bot", "crawler" | Whitelist `NOT agent: (*bot* OR *crawler*)` |
| Web admin login from trusted IP | `request: /admin/*` từ admin team IP | Whitelist `NOT clientip: ("10.x.x.x")` |
| Legitimate `phpmyadmin` for DB admin | Internal IT subnet | Whitelist source IP |
| `robots.txt` request — bot crawl bình thường | request = `/robots.txt` chỉ | Pattern không match `robots.txt` directly, nhưng skip vì có thể chứa `/backup` ở nội dung robots.txt |

**Production:** combine R8 với R7 (Suspicious UA) → nếu cả 2 fire cùng src_ip → severity = Critical.

## 5. Cấu hình rule trong Kibana

> ⚠️ Data view `dvwa-apache-*` đã tạo cho R7 — R8 reuse.

1. **Security → Rules → Detection rules → Create new rule** → **Custom query**.
2. Source Data View: `dvwa-apache-*`.
3. Paste KQL §2.
4. About:
   - **Name**: `[VN-SOC R8] Sensitive File Path Probe`
   - **Description**:
     ```
     Phát hiện HTTP request probe các path nhạy cảm (config file, admin
     panel, backup, system file). T1083 File and Directory Discovery.
     Attacker recon path nhạy cảm trước khi exploit. Cảnh báo sớm cho
     phép block IP trước khi attacker tìm thấy file/folder bị expose.
     Tham khảo: detection-rules/R8-T1083-sensitive-file-probe.md
     ```
   - **Severity**: Medium
   - **Risk score**: 47
   - **Tags**: `VN-SOC-Lab`, `Discovery`, `T1083`, `WebAttack`
   - **MITRE**: Tactic `Discovery (TA0007)` → Technique `File and Directory Discovery (T1083)`
5. Schedule: 5 min / 5 min look-back.
6. Create & enable.

## 6. Smoke-test

```bash
# Từ Kali — Directory bruteforce simulation
for path in .env .git/config wp-config.php phpmyadmin admin/login.php backup.zip "/../../etc/passwd" c99.php; do
    curl -s -o /dev/null "http://192.168.154.165:8080/$path"
done
```

**Đợi ≤5 phút** → Kibana → Security → Alerts → R8 fire ~8 alerts (1 per path).

## 7. Khi rule verified

- Export NDJSON → `detection-rules/R8-T1083-sensitive-file-probe.ndjson`.
- Update header status.
- Append CHANGELOG.
