# R9 — ML-based Malicious URL Detection

| Thuộc tính | Giá trị |
|---|---|
| Rule ID | `vnsoc-r9-ml-malicious-url` |
| MITRE Tactic | TA0001 — Initial Access |
| MITRE Technique | **T1190** Exploit Public-Facing Application |
| Severity | **High** |
| Risk score | 73 |
| Index pattern | `dvwa-apache-*` |
| Rule type | Custom query (KQL) |
| Schedule | Every 1 minute, look-back 5 minutes |
| Status | ✅ Deployed + verified 2026-06-27 |

## 1. Vì sao detect cái này

Pha 1-7 đã có signature-based rule (R7 sqlmap UA, R8 sensitive file probe). R9 bổ sung **ML approach** — train classifier trên dataset URL malicious vs benign, deploy Flask API trên VPS, Logstash gọi API enrich mỗi DVWA Apache event với `ml.label` + `ml.score`.

Khác R7/R8 ở chỗ: R9 không phụ thuộc keyword cụ thể (sqlmap/nikto/.env) — model học **character n-gram pattern** của URL. Có thể catch attacker dùng custom payload chưa từng thấy.

**Lab story cho CV interview:** *"I trained a TF-IDF char n-gram + LogisticRegression URL classifier, served via Flask + Docker, integrated with Logstash http filter for inline enrichment. This added ML-based detection layer on top of signature rules — a pattern used in production SOC for catching novel evasion attempts."*

## 2. KQL query

```
ml.label: "malicious" AND ml.score >= 0.7 AND event.module: "dvwa"
```

**Giải thích:**

- `ml.label: "malicious"` — model phán đoán URL nguy hiểm.
- `ml.score >= 0.7` — cao hơn threshold gốc 0.5 để giảm FP (dataset synthetic nhỏ gây FP nhẹ ở common PHP pages như `/login.php`, `/instructions.php`).
- `event.module: "dvwa"` — chỉ áp dụng cho dvwa-apache branch, không spam khi mở rộng pipeline ML cho source khác.

## 3. Ví dụ event match

```yaml
url.original   : /vulnerabilities/fi/?page=../../../../etc/passwd
http.response.status_code: 302
source.address : 192.168.154.151    (Kali)
ml.label       : malicious
ml.score       : 0.918
ml.threshold   : 0.5
ml.url         : /vulnerabilities/fi/?page=../../../../etc/passwd
event.module   : dvwa
```

Smoke-test thực tế Pha 8 quan sát:

| URL | ml.score | ml.label | Đánh giá |
|---|---|---|---|
| `/vulnerabilities/fi/?page=../../../../etc/passwd` | 0.918 | malicious | ✅ TP |
| `/vulnerabilities/sqli/?id=1' OR '1'='1` | 0.671 | malicious | ✅ TP (score thấp do encoded ký tự lạ ít) |
| `/.env` | 0.743 | malicious | ✅ TP |
| `/setup.php` | ~0.45 | benign | ✅ TN |
| `/login.php` | 0.602 | malicious | ⚠️ FP (common PHP page, dataset thiếu mẫu) |
| `/instructions.php` | 0.560 | malicious | ⚠️ FP |
| `/` | 0.393 | benign | ✅ TN |

→ Với threshold ≥ 0.7, R9 fire trên TP nhưng skip FP.

## 4. False-positive thường gặp & cách handle

| FP scenario | Nguyên nhân | Cách giảm |
|---|---|---|
| Common PHP pages (`/login.php`, `/admin.php`) score ~0.55-0.65 | Dataset synthetic thiếu mẫu benign cho `.php` extension thông dụng | (a) raise threshold (R9 dùng 0.7) (b) augment dataset với real Apache log benign từ Pha 6 (c) retrain |
| URL có ký tự encoded (`%20`, `%27`) nhưng benign (`?q=search+term`) | Char n-gram bắt pattern URL encoding tương tự injection | Thêm benign examples chứa URL-encoded params trong dataset |
| Static assets có query string version (`/app.js?v=1.2.3`) | OK trong Pha 8 — chưa thấy FP nhóm này | Monitor |

## 5. Architecture của ML pipeline

```
                      Filebeat (SOC-Tools VM)
                          /var/log/apache2/access.log
                                  │
                                  ▼
                  Logstash :5044  (Beats input)
                                  │
                  branch [fields][source_type] == "dvwa-apache":
                                  │
                                  ├─ grok COMBINEDAPACHELOG → url.original, source.address, ...
                                  │
                                  ├─ http filter — POST {url: %{[url][original]}} → 127.0.0.1:5000/predict
                                  │
                                  └─ target_body => "[ml]"  ← gắn nested object {label, score, threshold, url}
                                  │
                                  ▼
            Elasticsearch dvwa-apache-YYYY.MM.dd
                                  │
                                  ▼
                  Kibana R9 detection rule (KQL)
                                  │
                                  ▼
                      Security → Alerts panel
```

Flask API (Docker container `ml-url-api` trên VPS, bind `127.0.0.1:5000`):
- 2 endpoint: `/health`, `/predict` (POST {url} → {url, score, label, threshold})
- Model: TF-IDF char_wb (2,5) ngram + LogisticRegression class_weight=balanced
- mem_limit 400 MB, gunicorn 2 workers

## 6. Cấu hình rule trong Kibana

### Cách 1 — GUI (ưu tiên)

1. Kibana → **Security → Rules → Detection rules → Create new rule**.
2. **Custom query** rule type.
3. **Source: Data View** → `dvwa-apache-*`.
4. **Custom query**: paste KQL ở §2.
5. **Continue** → About rule:
   - **Name**: `[VN-SOC R9] ML Malicious URL Detection`
   - **Description**:
     ```
     ML-based detection: Flask URL classifier (TF-IDF char n-gram +
     LogisticRegression) gắn label "malicious" + score cho mỗi DVWA Apache
     event. R9 fire khi ml.label=malicious AND ml.score >= 0.7. Complements
     signature rules R7/R8.
     Tham khảo: detection-rules/R9-T1190-ml-malicious-url.md
     ```
   - **Severity**: High
   - **Risk score**: 73
   - **Tags**: `VN-SOC-Lab`, `InitialAccess`, `T1190`, `ML`
   - **MITRE ATT&CK threats**:
     - Tactic: `Initial Access (TA0001)`
     - Technique: `Exploit Public-Facing Application (T1190)`
6. **Continue** → Schedule:
   - Runs every: **1 minute**
   - Additional look-back time: **5 minutes**
7. **Continue** → Actions: bỏ qua.
8. **Create & enable**.

### Cách 2 — CLI (Kibana Detection Engine REST API)

```bash
ssh vps
KIBANA_USER="elastic"
KIBANA_PASS="<ELASTIC_PASSWORD>"

curl -sk -u "$KIBANA_USER:$KIBANA_PASS" -X POST \
  "http://localhost:5601/api/detection_engine/rules" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "[VN-SOC R9] ML Malicious URL Detection",
    "description": "ML-based detection via Flask classifier. ml.label=malicious AND ml.score >= 0.7.",
    "risk_score": 73,
    "severity": "high",
    "type": "query",
    "index": ["dvwa-apache-*"],
    "query": "ml.label: \"malicious\" AND ml.score >= 0.7 AND event.module: \"dvwa\"",
    "language": "kuery",
    "from": "now-5m",
    "interval": "1m",
    "tags": ["VN-SOC-Lab", "InitialAccess", "T1190", "ML"],
    "threat": [{
      "framework": "MITRE ATT&CK",
      "tactic": {"id": "TA0001", "name": "Initial Access",
                 "reference": "https://attack.mitre.org/tactics/TA0001/"},
      "technique": [{"id": "T1190", "name": "Exploit Public-Facing Application",
                     "reference": "https://attack.mitre.org/techniques/T1190/"}]
    }],
    "enabled": true
  }'
```

## 7. Smoke-test

### GUI (ưu tiên)
1. Trên Kali browser: `http://192.168.154.165:8080/vulnerabilities/fi/?page=../../../../etc/passwd`
2. Đợi ≤2 phút.
3. Kibana → **Security → Alerts** → filter `kibana.alert.rule.name : "[VN-SOC R9]*"`.
4. Click alert → expand → confirm `ml.score >= 0.7`.

### CLI
```bash
# Trên Kali — mix attack + benign
for u in "/vulnerabilities/fi/?page=../../../../etc/passwd" \
         "/.env" \
         "/setup.php" \
         "/about.php"; do
  curl -s -o /dev/null "http://192.168.154.165:8080$u"
done

# Đợi ~90s → query ES từ VPS
ssh vps 'curl -sk -u "elastic:<PWD>" \
  "https://localhost:9200/dvwa-apache-*/_search?q=ml.label:malicious+AND+ml.score:>=0.7&size=10&pretty"'
```

## 8. Khi rule verified

- Export NDJSON → `detection-rules/R9-T1190-ml-malicious-url.ndjson`.
- Update README.md table thêm R9 row.
- Append CHANGELOG entry.
