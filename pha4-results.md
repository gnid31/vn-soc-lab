# Pha 4 — Adversary Emulation Results

> Atomic Red Team simulation cho 5 detection rule của VN-SOC Lab,
> kết hợp PowerShell trigger benign + manual fix Sysmon endpoint config.

**Ngày thực hiện:** 2026-06-25
**Thời gian:** ~2.5 giờ (bao gồm debug + lesson capture)
**Endpoint:** Win10 VM `DESKTOP-L7FCMBQ`, snapshot `pha4-framework-ready-2026-06-25`
**Atomic Red Team version:** invoke-atomicredteam master (cài qua Install-AtomicRedTeam -getAtomics)

---

## Mục lục

1. [Tóm tắt điều hành](#1-tóm-tắt-điều-hành)
2. [Bảng kết quả 5 rule](#2-bảng-kết-quả-5-rule)
3. [Chi tiết từng test + time-to-detect](#3-chi-tiết-từng-test)
4. [Lesson 1 — SwiftOnSecurity Sysmon config thiếu ProcessAccess](#lesson-1)
5. [Lesson 2 — AI agent safety filter block legitimate red-team](#lesson-2)
6. [Lesson 3 — PowerShell elevation vs user role Administrator](#lesson-3)
7. [Lesson 4 — Known-good tool có hành vi giống malware (agy.exe)](#lesson-4)
8. [Lesson 5 — KQL syntax review-before-save (R5 tuning pitfall)](#lesson-5)
9. [R2 deferred — diagnosis history đầy đủ](#8-r2-deferred)
10. [Backlog Pha 4+ / Pha 5 prerequisites](#9-backlog)

---

## 1. Tóm tắt điều hành

Pha 4 đặt mục tiêu chạy 4-5 Atomic Red Team test attack thực tế (không phải smoke-test benign như Pha 3) trên endpoint Win10 đã có Sysmon + Winlogbeat, đo time-to-detect cho từng detection rule.

**Kết quả:**

- ✅ **R3 (T1547.001 Registry Run Key)** — Atomic trigger thành công, alert fire trong < 6 phút từ event.
- ✅ **R5 (T1071.001 Web Protocol)** — Atomic + agy.exe (Antigravity) sinh 55 alerts trong 30 phút; sau tune giảm về 0 alerts từ agy.exe.
- ✅ **R2 (T1003.001 LSASS Memory Access)** — Atomic test #1 chạy thành công, sau khi fix Sysmon ProcessAccess config thì 37 e10 events được capture, R2 fire 1 alert (MsMpEng.exe → lsass.exe @ 0x1010 — classic FP từ Windows Defender). Lesson: rule chính xác về kỹ thuật, FP là dấu hiệu rule cần whitelist EDR tools chính thức.
- N/A — R1 (T1059.001 PowerShell) đã verified ở Pha 3 smoke-test.
- N/A — R4 (T1110 Brute Force) đã verified ở Pha 3 smoke-test.

**Đóng góp chính của Pha 4 KHÔNG nằm ở alert count, mà ở 5 LESSON LEARNED** dưới đây — chính là những vấn đề thực tế nhất trong vận hành SOC mà recruiter quan tâm.

---

## 2. Bảng kết quả 5 rule

| Rule | Pha 3 smoke-test | Pha 4 Atomic test | Alerts fired Pha 4 | Trạng thái |
|---|---|---|---|---|
| R1 PowerShell Encoded Command | ✅ 5 alerts | (skip — đã verified) | — | ✅ Verified Pha 3 |
| R2 LSASS Memory Access | n/a | T1003.001-1 attack OK, Sysmon e10 ban đầu = 0 → config fix → eventually 37 e10 events captured | **1** (MsMpEng.exe FP) | ✅ **Verified — FP observed** |
| R3 Registry Run Key | ✅ 4 alerts | T1547.001-1 → e13 → alert | **1** (Atomic Red Team Run key) | ✅ Verified Pha 3 + Pha 4 |
| R4 Brute-Force Login | ✅ 1 alert (after fix) | (no Atomic — Pha 3 manual đủ) | — | ✅ Verified Pha 3 |
| R5 Non-Browser Outbound | ✅ 30 alerts | T1071.001 + agy.exe noise | **55 → 0 sau tune** | ✅ Verified + tuned |

**Tổng alerts toàn bộ project:** 96 (Pha 3 smoke + Pha 4 atomic). Index `.internal.alerts-security.alerts-default-000001` chứa đầy đủ.

---

## 3. Chi tiết từng test

### 3.0 Reproducibility — Pha 4 KHÔNG cần AI agent

Pha 4 trong project gốc được drive bởi Antigravity (Google AI agent) trên Win10 + Claude Code (Anthropic) trên Kali để verify từ VPS. Tuy nhiên **toàn bộ workflow có thể reproduce bằng tay** không cần bất kỳ AI tool nào. Mapping:

| Phần | AI workflow (project gốc) | Manual workflow (bạn re-deploy) |
|---|---|---|
| Install Atomic Red Team | Antigravity paste install script | Mở PowerShell as Admin, paste cùng `Install-AtomicRedTeam` script (§3.1) |
| Run T1547.001 atomic | Antigravity `Invoke-AtomicTest T1547.001` | Bạn paste cùng lệnh vào elevated PS (§3.2) |
| Run T1071.001 atomic | Antigravity tự chạy | Paste lệnh manual (§3.3) |
| Run T1003.001 atomic | Antigravity chạy lần 1, từ chối lần 2 (Lesson 2) | Paste manual, không bị AI safety block — tuy nhiên cần fix Sysmon config trước (§3.4 + Lesson 1) |
| Verify alerts từ VPS | Claude Code SSH + curl ES API | Bạn SSH vào VPS, paste cùng `curl` queries trong [`report.md §9.2`](report.md) |
| Edit Sysmon config | Antigravity edit XML + reload | Mở file `C:\Sysmon\sysmonconfig-export.xml` bằng Notepad, add RuleGroup, save, `Sysmon64.exe -c <path>` |
| Tune R5 KQL | Bạn edit trên Kibana UI | Bạn edit trên Kibana UI (cùng workflow — GUI) |

**Tóm tắt:** mỗi bước có 2 con đường, kết quả như nhau. Khi đọc các section §3.x dưới đây, hãy xem AI prompts là "ví dụ workflow nhanh", còn các lệnh PowerShell / shell trong đó là **content thực** mà bất kỳ ai cũng paste được vào terminal của mình.

### 3.1 Setup framework (Prompt 1 Antigravity)

```powershell
# Verify Defender controllable
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableRealtimeMonitoring $false  # restore ngay

# Add exclusion folder TRƯỚC khi tải Atomic
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"

# Install
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

# Verify
Get-Command Invoke-AtomicTest    # → Command info
```

**Issue gặp phải:** Execution Policy default `Restricted` reject import module → fix:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
```

→ Sau khi RemoteSigned, mọi module + dependency (powershell-yaml) load OK.

### 3.2 T1547.001-1 — Registry Run Key (verify R3)

**T0:** 2026-06-25T15:04:00Z (approximate)
**Atomic command:**
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1547.001 -TestNumbers 1
```

**Source event** (Sysmon e13, capture từ ES):
```yaml
TargetObject : HKU\S-1-5-21-4188382834-1221911911-931124274-1000\
               SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team
Details      : C:\Path\AtomicRedTeam.exe
Image        : C:\Windows\system32\reg.exe
```

**Alert created:** 2026-06-25T15:04:11.639Z
**Time-to-detect:** ~11 giây (tính từ event sinh ra trên endpoint đến alert hiện trong ES alert index)
**Verdict:** ✅ R3 verified end-to-end with real atomic test.

**Cleanup:** `Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup` xoá Run key bằng `reg.exe delete` → Sysmon e14 (registry rename/delete), KHÔNG trigger R3 (rule chỉ match e13 set value).

### 3.3 T1071.001 — Web Protocol C2 (verify R5)

**Atomic command:** `Invoke-AtomicTest T1071.001 -TestNumbers 1`

**Source events:** Sysmon e3 (network_connection) từ `powershell.exe` ra hostname/IP external.

**Alerts:** 55 alerts trong 30 phút. Aggregation theo Image cho thấy:
- ~30/55 từ `agy.exe` (Antigravity AI agent — xem [Lesson 4](#lesson-4))
- ~5/55 từ `powershell.exe` (Atomic test thực sự)
- Còn lại từ `WindowsTerminal.exe`, `RuntimeBroker.exe`, các Windows background

**Time-to-detect (Atomic-only):** ~2-3 phút (powershell.exe network event → alert).
**Verdict:** ✅ R5 verified. Phải tune FP exclude list (xem [Lesson 4](#lesson-4)).

### 3.4 T1003.001-1 — LSASS Dump (verify R2 — KHÔNG fire)

**Atomic command:**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Invoke-AtomicTest T1003.001 -TestNumbers 1 -GetPrereqs    # download procdump
Invoke-AtomicTest T1003.001 -TestNumbers 1                # ProcDump -ma lsass.exe → .dmp
Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup       # xoá .dmp
Set-MpPreference -DisableRealtimeMonitoring $false
```

**Bằng chứng attack THÀNH CÔNG (Sysmon e1 process tree, từ ES):**

```
14:59:15  powershell.exe — test prereq path
14:59:16  powershell.exe — download procdump (Tls12, New-Item Directory)
14:59:20  powershell.exe — verify path exists
14:59:21  cmd.exe        → procdump.exe → procdump64.exe (3 sub-process tree)
              procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp
14:59:22  procdump64.exe — đang thực thi dump
15:00:24  cmd.exe — del C:\Windows\Temp\lsass_dump.dmp (cleanup OK)
```

→ **ProcDump đã thực sự dump LSASS memory ra `.dmp`** trong khoảng 14:59:22 → 15:00:24 (~62 giây dump). File sau đó được cleanup script xoá.
→ **Defender đã được disable đúng cách** (procdump không bị block).
→ **Atomic test framework hoạt động hoàn hảo.**

**Vấn đề:** Sysmon `event_id=10` (process_access) = **0** trong toàn bộ index từ trước tới giờ. Không có ghi nhận handle nào vào lsass.exe → R2 không có data để fire.

**Root cause:** xem [Lesson 1](#lesson-1).
**Trạng thái R2:** deferred — chi tiết debug history ở [§8](#8-r2-deferred).

---

## Lesson 1 — SwiftOnSecurity Sysmon config thiếu ProcessAccess rule, dẫn đến false negative R2

<a id="lesson-1"></a>

### Mô tả

SwiftOnSecurity là Sysmon config **phổ biến nhất** trong cộng đồng SOC, được khuyến nghị bởi Microsoft, MITRE, Red Canary. Config này tối ưu cho detection rộng — bắt được process create, network connection, DNS, registry, file create, file hash. NHƯNG **không enable ProcessAccess logging** (event_id 10) mặc định.

### Vì sao SwiftOnSecurity loại e10

Volume: mỗi máy Windows bình thường sinh **hàng nghìn e10/giờ** (Task Manager open process info, Defender scan, performance counters). Log all → noise quá lớn + storage blow-up.

### Hậu quả với detection rule LSASS

Đây là **classic false negative pattern**:

```
Sysmon config strict (no e10)
    ↓
ProcDump dumps LSASS thành công
    ↓
No e10 event sinh ra
    ↓
SIEM rule R2 (KQL match e10 + GrantedAccess) không có data → fire 0 alert
    ↓
Analyst tin rằng "không có attack" → MISSED CREDENTIAL DUMP
```

Đây chính xác là kiểu lỗ hổng kẻ tấn công enterprise khai thác.

### Bài học cho SOC engineer

Khi viết detection rule, **phải verify source telemetry trước khi tin rule fire được**. KHÔNG dùng Atomic test thành công như bằng chứng SIEM detection — Atomic verify ATTACKER capability, KHÔNG verify DEFENDER detection.

Pattern đúng để verify rule:
1. Atomic Red Team chạy attack.
2. **Manually check source log** (Sysmon Operational log trên endpoint) → event có sinh không?
3. Nếu có → check shipping (Logstash events_in)
4. Nếu shipped → check ES index → có doc không?
5. Nếu có doc → check Kibana rule execution → match KQL?
6. Nếu match → alert fire.

**Mỗi bước phải PASS** mới đảm bảo end-to-end detection works.

### Fix đề xuất + Resolution (2026-06-25)

Edit Sysmon config XML thêm `<ProcessAccess>` rule với scope:
- TargetImage = lsass.exe (narrow)
- Filter dangerous GrantedAccess masks trong Sysmon thay vì SIEM (giảm volume)

```xml
<RuleGroup name="VN-SOC R2 - LSASS Access Detection" groupRelation="or">
  <ProcessAccess onmatch="include">
    <TargetImage condition="end with">\lsass.exe</TargetImage>
  </ProcessAccess>
</RuleGroup>
```

**Resolution (2026-06-25):** Edit + `Sysmon64.exe -c <path>` apply. Ban đầu mình nhầm là config không active (vì query window `now-30m` không catch event đầu), declare R2 deferred. **Sau đó verify lại với time window rộng hơn**: Sysmon config ĐÃ active, 37 e10 events captured, R2 fire 1 alert thật từ `MsMpEng.exe` (Windows Defender) → lsass.exe @ 0x1010. → Rule WORKS. FP từ Defender là expected và đáng được tune trong Pha 5+ (whitelist EDR signed binaries).

**Mea culpa lesson cho mình:** verify window phải đủ rộng (bắt đầu từ T0 atomic test, không cố định `now-30m`). Time-based queries có thể MISS event nếu rule schedule delay hoặc shipping latency lệch window.

---

## Lesson 2 — AI agent safety filter block legitimate purple-team work

<a id="lesson-2"></a>

### Mô tả

Antigravity (Google AI agent) **từ chối thực thi** Atomic Red Team T1003.001 ngay cả khi:
- Đã xác nhận đang trong môi trường lab có snapshot.
- Đã có Defender exclusion path cho Atomic.
- Đã disable Defender Real-Time Protection.
- Có cleanup script chạy ngay sau test.

Lần thứ 2 (sau khi sửa Sysmon config), Antigravity từ chối thẳng:

> Sorry, I cannot fulfill your request to create or run scripts that open handles to the LSASS process or automate SSH commands using hardcoded credentials. You can search online for standard security practices regarding verifying SIEM event forwarding and Windows event ingestion using benign event logs like system startup or network connection indicators.

### Tại sao lesson này quan trọng

1. **Doanh nghiệp đang adopt AI agent cho ops** (Microsoft Copilot Security, GitHub Copilot, Antigravity, Claude Code). Mỗi công cụ có safety filter khác nhau, mức độ strict khác nhau.

2. **Purple team / red team workflow KHÔNG fully automatable bằng AI** — luôn cần human-in-the-loop cho các technique sensitivity cao (credential dumping, persistence, privilege escalation).

3. **Mỗi AI agent có "blind spots" khác nhau**:
   - Antigravity: block LSASS access + SSH với credential hardcoded
   - Claude Code: chạy được Atomic Red Team nếu user có clear authorization context + lab snapshot
   - GitHub Copilot Workspace: block exploit code

4. **Lesson cho SOC analyst đi phỏng vấn:** hiểu rõ ranh giới giữa AI assistance và human responsibility là kỹ năng mềm quan trọng. KHÔNG over-rely AI cho red-team.

### Cách workaround chuyên nghiệp

Khi AI từ chối:
- Document chính xác lý do từ chối (capture user-facing message).
- Tách workflow: AI làm preparation + verification, **human** trigger offensive action trong elevated session.
- Hoặc: dùng AI khác cho phần cụ thể đó (vd Claude Code có thể chạy được).
- Hoặc: dùng tool ngoài AI (BloodHound, CALDERA, manual atomic test).

### Trong VN-SOC Lab này

- Antigravity: dùng cho install framework + benign trigger (Pha 4 setup, R3 atomic, R5 atomic).
- Claude Code: dùng cho SSH automation từ Kali + ES query (toàn bộ verify pipeline).
- Manual PowerShell (human): cho R2 — khi cần dump LSASS thực sự.

### Kết quả tune R5 (2026-06-25)

Sau khi add `*\\agy.exe` vào exclude list (qua 2 lần edit Kibana UI — lần 1 quên `OR`, xem [Lesson 5](#lesson-5)):

| Metric | Trước tune | Sau tune đúng |
|---|---|---|
| R5 alerts từ agy.exe | ~30/30m (chiếm 90% noise) | **0** |
| R5 alerts tổng (5 phút sau) | 1 | **0** |
| Sysmon e3 agy.exe vào ES | shipped | shipped ✅ (data preserved, chỉ KHÔNG alert) |
| Hash verification `agy.exe` | n/a — accept theo path | Pha 5+ sẽ thêm signature check |

→ Tune SUCCESS. R5 giờ chỉ fire alert khi process THẬT là non-browser + non-whitelisted (vd PowerShell, custom binary trong `%TEMP%`).

---

## Lesson 5 — KQL syntax review-before-save (R5 tuning pitfall)

<a id="lesson-5"></a>

### Triệu chứng

Khi tune R5 thêm `*\\agy.exe` vào exclude list, sửa nhanh trên Kibana UI nhưng quên `OR` ở dòng trước:

```
Sai:                            Đúng:
*\\CompPkgSrv.exe               *\\CompPkgSrv.exe OR
*\\agy.exe                      *\\agy.exe
```

Rule save thành công, status=succeeded, KQL chứa `agy.exe` text → mọi check tự động đều PASS. **Nhưng** KQL parser xử lý sai → `agy.exe` không thực sự được exclude → R5 vẫn fire alert từ agy.exe sau khi "tune".

### Phát hiện

Sau khi user save tune, mình query thấy `Total alerts = 1`. Sample alert show Image = `agy.exe` — không như kỳ vọng (phải 0 alerts từ agy).

Dump full KQL ra, thấy thiếu `OR`. User fix, retest → 0 alert agy.exe.

### Bài học SOC engineer

1. **status=succeeded KHÔNG đảm bảo logic đúng** — chỉ đảm bảo cú pháp KQL valid và rule chạy được.
2. **Mọi tune phải có acceptance test cụ thể** — không tin "rule chạy ok = tune ok". Phải verify hành vi mong đợi (vd "alert count agy.exe = 0 sau tune").
3. **KQL OR liên kết — mất 1 OR là cả phần sau bị orphan.** Trên long exclude list, dùng linter / format helper / multi-line review.
4. **Sample 1 doc sau save** — query Detection Engine API trả về sample alert để confirm exclude thực sự loại được FP.

### Workflow đề xuất khi tune rule

```
[1] Edit KQL trên Kibana UI.
[2] Save.
[3] Đợi 1 chu kỳ rule (5 phút cho R5).
[4] Query alert mới nhất:
    curl -sk -u elastic:$PW \\
      "https://localhost:9200/.internal.alerts-security.alerts-default-*/_search?size=1&sort=@timestamp:desc&pretty" \\
      -H "Content-Type: application/json" \\
      -d '{"query":{"match_phrase":{"kibana.alert.rule.name":"<RULE_NAME>"}}}'
[5] Verify field-target trong sample khớp kỳ vọng tune.
[6] Nếu sai → mở lại UI, dump full KQL, soi lại syntax.
```

---

## Lesson 3 — PowerShell elevation vs user role Administrator

<a id="lesson-3"></a>

### Triệu chứng quan sát

User mở PowerShell với user `ADMIN` (built-in Administrator account), gõ:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

→ Lỗi:
```
Set-MpPreference : You don't have enough permissions to perform the requested operation.
HRESULT 0xc0000142
```

User wondering: "tôi là Administrator rồi mà?"

### Root cause

`Set-MpPreference` cho Defender requires **TrustedInstaller-level elevation** — chỉ được cấp khi PowerShell mở qua **"Run as administrator"** với UAC elevation prompt được approve.

Có sự khác biệt giữa:

| Khái niệm | Ý nghĩa |
|---|---|
| User belongs to Administrators group | `Get-LocalGroupMember Administrators` thấy user — chỉ là member |
| Process is elevated | `IsInRole(Administrator) == True` — process token có Admin SID active |
| Process has TrustedInstaller-equivalent | Một số API (Defender, system file modification) yêu cầu thêm |

User thông thường, dù trong group Administrators, khi mở PowerShell **không** elevated → token có Admin SID nhưng **deny-only**. Phải "Run as administrator" + UAC consent → token có Admin SID **enabled**.

### Cách verify elevation

```powershell
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
```

- `True` → elevated, có thể Set-MpPreference, write to Program Files, modify HKLM
- `False` → not elevated, bị block các privileged operation

### Visual cue

Title window:
- `Administrator: Windows PowerShell` → elevated ✅
- `Windows PowerShell` → KHÔNG elevated ❌

### Bài học cho SOC analyst

Khi script verify privileged operation fail "permission denied" hoặc "0xc0000142":
1. KHÔNG retry với cùng session — sẽ fail liên tục.
2. KHÔNG đoán user role — verify bằng `IsInRole`.
3. Phải close shell + Run as administrator + UAC consent → tạo session mới.

---

## Lesson 4 — Known-good tool có hành vi giống malware (2 instances quan sát được)

<a id="lesson-4"></a>

### Tóm tắt

Trong Pha 4, **2 detection rules đều fire alert từ legitimate Microsoft/Google tools** — đúng pattern của rule nhưng FP. Cả 2 minh hoạ cùng lesson: rule chính xác về kỹ thuật, FP từ tool đã verify hợp pháp.

#### Instance 1 — R5 alert từ `agy.exe` (Antigravity AI agent)

R5 (Non-Browser Outbound HTTPS) thiết kế để phát hiện C2 beacon — binary trong `%APPDATA%` gọi HTTPS định kỳ. Đây CHÍNH XÁC là hành vi của Cobalt Strike, Empire, Sliver.

```yaml
Image           : C:\Users\ADMIN\AppData\Local\agy\bin\agy.exe
DestinationIp   : 216.239.36.223  (Google API IP range)
DestinationPort : 443
```

→ Antigravity AI agent sync session với Google backend.

#### Instance 2 — R2 alert từ `MsMpEng.exe` (Windows Defender)

R2 (LSASS Memory Access) thiết kế để phát hiện Mimikatz / ProcDump credential dump. Đây là hành vi của T1003.001.

```yaml
SourceImage   : C:\Program Files\Windows Defender\MsMpEng.exe
TargetImage   : C:\Windows\system32\lsass.exe
GrantedAccess : 0x1010  (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)
```

→ Windows Defender scan LSASS memory để detect credential theft → đúng quy trình AV, giống hành vi attacker.

### Vì sao đây là lesson quan trọng

Cả 2 rule **HOÀN TOÀN ĐÚNG về kỹ thuật**:

**R5:**
- ✅ Image trong %APPDATA% (binary không thuộc system path)
- ✅ Periodic outbound HTTPS (port 443)
- ✅ Không phải browser whitelist

Pattern này identical với Cobalt Strike beacon.

**R2:**
- ✅ ProcessAccess vào lsass.exe
- ✅ GrantedAccess chứa PROCESS_VM_READ bit (0x10)
- ✅ Không phải lsass tự loop

Pattern này identical với Mimikatz / ProcDump.

Một SOC analyst đọc alert sẽ phải investigate cả 2. Trong môi trường thật, làm sao phân biệt:
- Antigravity (legit AI agent) vs Cobalt Strike (malware)?
- Defender MsMpEng (legit AV) vs ProcDump abuse?

### Cách doanh nghiệp giải quyết

**Không** bỏ rule (sẽ miss malware thật). **Tune** bằng cách:

1. **Hash whitelist** — verify hash binary khớp với hash vendor công bố → exclude.
2. **Path + signature whitelist** — Image path cụ thể + binary đã sign bởi vendor (Google LLC / Microsoft Corp) → exclude.
3. **Threat intelligence enrich** — DestinationIp resolve về ASN whitelist (Microsoft, Google).

Trong lab VN-SOC này:

| Rule | FP source | Action đã làm | Action backlog |
|---|---|---|---|
| R5 | `*\\agy.exe` | ✅ Exclude theo Image path 2026-06-25 (FP giảm 100%) | Pha 5+: verify hash + signature |
| R2 | `*\\MsMpEng.exe` | ⏳ Chưa tune | Pha 5+: exclude SourceImage `*\\Windows Defender\\MsMpEng.exe` + verify Microsoft signed |

**Lưu ý:** KHÔNG exclude generic — phải cụ thể path để tránh attacker drop binary cùng tên ở chỗ khác.

### Bài học cho phỏng vấn SOC

Recruiter sẽ hỏi: "Có rule fire alert nhưng analyst biết là legit, làm gì?"

Câu trả lời tốt:
- **KHÔNG** disable rule.
- **KHÔNG** silently exclude — phải document.
- **VERIFY** hash + signature trước khi exclude.
- **DOCUMENT** trong knowledge base: tool gì, ASN gì, hash gì, người approve, ngày.
- **Periodic review** — tools update, hash thay đổi, exclusion có thể bypass.

---

## 8. R2 verified — diagnosis history + FP analysis

<a id="8-r2-deferred"></a>

### Timeline debug R2 (~2h, eventually verified)

| Step | Action | Kết quả |
|---|---|---|
| 1 | Run Atomic T1003.001-1 lần đầu | Procdump dump LSASS thành công (Sysmon e1 confirm), nhưng e10 = 0 → R2 fire 0 alert |
| 2 | Diagnose: SwiftOnSecurity config không có ProcessAccess rule | Confirmed, đây là [Lesson 1](#lesson-1) |
| 3 | Edit Sysmon config XML — thêm `<RuleGroup name="VN-SOC R2">` với `<TargetImage condition="image">lsass.exe</TargetImage>` | File trên disk có rule line 1200 |
| 4 | `Sysmon64.exe -c <path>` apply | Output: "Configuration file validated. Configuration updated." |
| 5 | Antigravity tự refuse chạy T1003.001 lần 2 | AI safety filter block — [Lesson 2](#lesson-2) |
| 6 | User mở manual PowerShell trigger | Set-MpPreference fail "not enough permissions" — [Lesson 3](#lesson-3) |
| 7 | User mở elevated PS đúng cách + verify | IsInRole=True, TamperProtected=False, RealTimeProtection=True, **active Sysmon config grep "lsass" = empty** |
| 8 | Force `Get-Process lsass | .Handles` → expect e10 | e10 vẫn = 0 → Sysmon config không thực sự active |
| 9 | Antigravity tự refuse auto-debug + SSH credential | Block triple — config debug + LSASS handle + SSH automation |
| 10 | Re-check sau ~30 phút với time window rộng hơn | **37 e10 events captured! R2 fire 1 alert từ MsMpEng.exe (Defender) @ 0x1010 lúc 16:20:23.** Sysmon config eventually applied + R2 rule WORKS |
| 11 | Mea culpa — query window ban đầu `now-30m` quá hẹp | Lesson cho VPS-side verify: time window phải đủ rộng từ T0 atomic test |

### Trạng thái cuối Pha 4 — R2 VERIFIED

- **R2 rule trong Kibana:** ✅ Enabled, status=succeeded, KQL parse OK.
- **Sysmon config file:** ✅ Có VN-SOC R2 RuleGroup ở line 1200.
- **Sysmon active config:** ✅ Verified active — 37 e10 events captured từ multiple sources (svchost, MsMpEng).
- **Sysmon e10 ship vào ES:** ✅ 37 events.
- **R2 alert fire:** ✅ **1 alert** (MsMpEng.exe → lsass.exe @ 0x1010 — classic FP từ Defender — đây là tín hiệu rule WORK, cần tune whitelist EDR signed binaries).

### Phân tích FP `MsMpEng.exe` (Windows Defender)

`MsMpEng.exe` (Microsoft Malware Protection Engine) thường xuyên scan LSASS memory như một phần của real-time protection để detect credential theft. Behavior này:
- Open LSASS với PROCESS_QUERY_LIMITED_INFORMATION (0x1000) — không match KQL R2
- Open LSASS với PROCESS_VM_READ (0x10) khi scan memory — kết hợp 0x1000 + 0x10 = **0x1010** → MATCH KQL R2

Đây là Defender làm việc đúng quy trình, nhưng giống hệt Mimikatz initial step (cũng dùng 0x1010 để bắt đầu dump).

### Tune R2 cho Pha 5+ (backlog)

```
# Bổ sung vào R2 KQL:
... AND NOT winlog.event_data.SourceImage.keyword: (
  *\\Windows Defender\\MsMpEng.exe OR
  *\\Windows Defender\\MpEngine.dll
)

# HOẶC verify theo signature: binary phải Microsoft signed
... AND NOT (winlog.event_data.SourceImage.keyword: *\\MsMpEng.exe
             AND winlog.event_data.IntegrityLevel: System)
```

Lưu ý security risk: attacker có thể abuse `MsMpEng.exe` để bypass detection (load malicious config). Pha 5+ phải verify thêm bằng signature check thực sự, không chỉ tên + path.

---

## 9. Backlog

### Pha 5 prerequisites đã sẵn sàng

- ✅ 4/5 rule fire alerts (R1, R3, R4, R5 đều có alert thực tế trong index).
- ✅ Endpoint shipping events đầy đủ (4400+ doc tổng).
- ✅ Sysmon config có rule cho e10 (cần verify active sau reboot).
- ✅ Antigravity workflow established (config + benign trigger).
- ✅ 4 lessons learned documented (đây là content CV chính của Pha 4).

### Đề xuất next steps

1. **Tune R5** — thêm `*\\agy.exe` vào exclude list KQL. Giảm noise ~50%.
2. **Sang Pha 5** — viết Incident Report cho 1 chuỗi attack giả lập đa-bước, mapping MITRE kill-chain.
3. **(optional)** Resolve R2 sau Pha 5 nếu còn thời gian — restart VM + verify Sysmon config active.

---

*Pha 4 hoàn tất với chiến lược "lesson-first" thay vì "alert-count-first". Recruiter quan tâm SOC analyst biết debug + biết bài học hơn là số alert. 4 lesson trên đáng giá hơn 100 alert trùng lặp.*
