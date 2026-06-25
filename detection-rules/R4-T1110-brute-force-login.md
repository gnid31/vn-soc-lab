# R4 — Multiple Failed Logon — Brute Force

| Thuộc tính | Giá trị |
|---|---|
| Rule ID | `vnsoc-r4-brute-force-login` |
| MITRE Tactic | TA0006 — Credential Access |
| MITRE Technique | **T1110** Brute Force |
| Severity | **High** |
| Risk score | 73 |
| Index pattern | `winlogbeat-*` |
| Rule type | **Threshold** (KHÔNG phải Custom query) |
| Threshold | `≥ 5` events trong window, group by `winlog.event_data.TargetUserName.keyword` |
| Schedule | Every 1 minute, look-back 5 minutes |
| Status | ✅ Deployed + smoke-test verified 2026-06-25 (1 alert fired sau fix config) |

## 1. Vì sao detect cái này

Brute-force = thử nhiều password khác nhau cho cùng 1 username. Source phổ biến trong môi trường VN:

- **External RDP** (port 3389 expose ra Internet) — botnet quét liên tục.
- **SMB / NTLM relay** trên LAN — attacker đã có foothold thử lateral.
- **Local console** — insider attacker thử mò password.

Windows Security log event `4625 (Audit Failure — An account failed to log on)` được ghi cho MỌI lần failed login. Trên endpoint workstation bình thường, 4625 trong 1 phút thường = 0. ≥5 trong 1 phút = brute-force chắc chắn.

**Tại sao threshold rule, không phải query rule:** 1 sự kiện 4625 đơn lẻ là **bình thường** (user gõ sai password). Chỉ khi ĐẾM ≥5 trong khung thời gian ngắn mới là threat. Threshold rule type được thiết kế cho đúng trường hợp này.

## 2. Cấu hình rule

### 2.1 Custom query filter (chứ KHÔNG phải full KQL detection logic)

KQL chỉ filter event nào ĐƯỢC đếm. Threshold counting là phần riêng:

```
event.code: "4625" AND winlog.channel: "Security"
```

### 2.2 Threshold setting

| Setting | Value | Giải thích |
|---|---|---|
| **Group by field** | `winlog.event_data.TargetUserName.keyword` | Đếm fail theo username. 5 fail vào user A và 5 fail vào user B → 2 alert riêng |
| **Threshold value** | `5` | 5 fail mới fire — tránh false-positive user gõ sai 1-2 lần |
| Cardinality field | _(bỏ trống)_ | Không cần thêm điều kiện distinct |

> ⚠️ **Pitfall đã gặp 2026-06-25:** trong Kibana UI tab Definition, có 2 phần **Threshold** và **Cardinality** trông giống nhau. Phải đặt `TargetUserName.keyword` vào **THRESHOLD field** (group-by), KHÔNG phải Cardinality field. Cardinality đếm số *distinct value*; smoke-test dùng 1 username duy nhất → cardinality=1 < threshold=5 → rule không fire dù KQL match 12+ events. Lần đầu config sai mất 30 phút debug. Nhớ kỹ.

### 2.3 Schedule (khác R1-R3)

- **Runs every: 1 minute** (không phải 5 minutes)
- **Additional look-back: 4 minutes** (tổng look-back 5 phút)

Lý do schedule ngắn hơn: brute-force diễn ra trong giây/phút. Lookback 5 phút đủ để đếm burst, không quá rộng gây alert quá trễ.

## 3. Ví dụ event match

```yaml
# Lặp lại ≥5 event như sau trong vòng 5 phút, cùng TargetUserName
event.code              : "4625"
winlog.channel          : "Security"
winlog.event_data.TargetUserName     : "Administrator"
winlog.event_data.TargetDomainName   : "DESKTOP-L7FCMBQ"
winlog.event_data.IpAddress          : "192.168.56.10"   (nếu remote)
winlog.event_data.LogonType          : "3"  (Network) / "10" (RDP) / "2" (Interactive)
winlog.event_data.Status             : "0xC000006D"   (status code = bad username/password)
winlog.event_data.SubStatus          : "0xC000006A"   (sub-status = wrong password)
```

→ Threshold counting 5+ trong 5' → alert.

## 4. False-positive thường gặp

| FP scenario | Đặc trưng | Khuyến nghị |
|---|---|---|
| User quên password thật | Cùng IP local, LogonType=2 (interactive) | Chấp nhận — IT helpdesk xử lý, hoặc raise lên user training |
| Service account password expired | TargetUserName = service account, LogonType=5 | Loại trừ pattern user service (vd `*$` cho machine account) |
| Script tự động sai credential | Cùng SourceMachine, lặp rất nhanh | Chấp nhận — đây cũng là dấu hiệu config sai |
| RDP bot từ Internet | IP public, LogonType=10 | **Không phải FP — đáng alert, escalate cao** |

**Pha 4 sẽ tinh chỉnh sau khi observe FP rate thực tế.**

## 5. Cấu hình rule trong Kibana

1. Kibana → **Security → Rules → Detection rules → Create new rule**.
2. **Threshold** (chọn type này, không phải Custom query).
3. Source: Data view `winlogbeat-*`.
4. **Custom query**: `event.code: "4625" AND winlog.channel: "Security"`.
5. **Threshold**:
   - Field: `winlog.event_data.TargetUserName.keyword`
   - Value: `5`
6. **Continue** → About rule:
   - **Name**: `[VN-SOC R4] Multiple Failed Logon — Brute Force`
   - **Description**:
     ```
     Threshold rule: phát hiện ≥5 lần đăng nhập fail (Security event 4625)
     cùng 1 TargetUserName trong cửa sổ 5 phút. Đặc trưng của brute-force
     password — T1110. Source phổ biến: external RDP (Internet expose),
     SMB/NTLM relay LAN, local console insider.
     Tham khảo: detection-rules/R4-T1110-brute-force-login.md
     ```
   - **Severity**: High
   - **Risk score**: 73
   - **Tags**: `VN-SOC-Lab`, `CredentialAccess`, `T1110`, `BruteForce`
   - **MITRE ATT&CK**:
     - Tactic: `Credential Access (TA0006)`
     - Technique: `Brute Force (T1110)` (không cần sub-technique cho rule chung)
7. **Continue** → Schedule:
   - Runs every: **1 minute**
   - Additional look-back time: **4 minutes**
8. **Continue** → Actions: bỏ qua.
9. **Create & enable**.

## 6. Smoke-test (an toàn — fail login chính account của bạn)

Trên Win10, PowerShell as Administrator (account ADMIN), test 6 lần fail bằng `net use` với password sai:

```powershell
# 6 lần thử connect IPC$ với fake password — sinh 6 event 4625
for ($i = 1; $i -le 6; $i++) {
    Write-Host "Attempt $i..."
    net use \\127.0.0.1\IPC$ /user:fakeuser_$i WrongPassword123 2>&1 | Out-Null
    Start-Sleep -Seconds 2
}
```

Mỗi `net use` fail sinh 1 event 4625 với TargetUserName khác (`fakeuser_1`, `fakeuser_2`, ...). **6 username khác nhau** thì threshold theo từng user sẽ KHÔNG đạt 5.

**Phải dùng cùng 1 username để vào threshold:**

```powershell
# 6 lần với CÙNG 1 fake username — threshold sẽ fire
for ($i = 1; $i -le 6; $i++) {
    Write-Host "Attempt $i..."
    net use \\127.0.0.1\IPC$ /user:VnSocBruteTest WrongPassword$i 2>&1 | Out-Null
    Start-Sleep -Seconds 2
}
```

**Đợi ≤2 phút** (rule chạy mỗi 1 phút) → Kibana → Security → Alerts → thấy alert `[VN-SOC R4]` với TargetUserName=`VnSocBruteTest`, count=6.

**Cleanup:** không cần — `net use` fail không tạo persistence/registry/file. Có thể xoá session: `net use * /delete /y` (nếu lỡ có session nào dính).

## 7. Khi rule đã verified

- Export NDJSON → `detection-rules/R4-T1110-brute-force-login.ndjson`.
- Update header table: Status = ✅ Deployed + verified `<date>`.
- Append CHANGELOG entry.
