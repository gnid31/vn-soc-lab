# INCIDENT REPORT — VN-SOC-2026-0001

> **Suspected adversary intrusion attempt on workstation DESKTOP-L7FCMBQ**
> *Kill-chain analysis — Execution → Persistence → Credential Access*

---

## Incident metadata

| Field | Value |
|---|---|
| Incident ID | `VN-SOC-2026-0001` |
| Severity | **High** (multiple MITRE TA tactics observed within 18 minutes) |
| Status | **Contained** (snapshot restore + alerts triaged) |
| Date detected | 2026-06-25 10:34 UTC (17:34 ICT) |
| Date contained | 2026-06-25 18:00 UTC (01:00 ICT next day) |
| Reporter | gnid31 (SOC Analyst T1) |
| Affected host | DESKTOP-L7FCMBQ (Windows 10, domain user `ADMIN`) |
| Detection source | VN-SOC Lab Elastic SIEM rules R1 + R3 + R4 |
| Containment lead | gnid31 |
| Lab/synthetic note | This report uses **real alerts generated in a controlled lab** (Atomic Red Team + manual smoke-test). Narrative reconstructs them as an adversary chain for SOC analyst training. Methodology and analytical workflow are production-equivalent. |

---

## 1. Executive summary

Within an 18-minute window on 2026-06-25 (10:34 → 10:52 UTC), workstation `DESKTOP-L7FCMBQ` exhibited a **coordinated chain of three MITRE ATT&CK tactics** by a local administrator account:

1. **Persistence** (T1547.001) — two Registry Run keys were created within minutes of each other, scheduled to execute on every user logon.
2. **Execution** (T1059.001) — PowerShell process launched with `-EncodedCommand` parameter containing Base64-encoded payload, a known indicator of evasion-by-encoding used by Emotet, Cobalt Strike, and other commodity loaders.
3. **Credential Access** (T1110) — six failed logon attempts against fictitious account `VnSocBruteTest` within ~12 seconds, matching brute-force threshold.

A fourth event later in the day (T1003.001 LSASS access at 16:20) was confirmed as **false positive** from Windows Defender real-time scanning, but illustrated an additional FP class observed during analysis.

**No data was confirmed exfiltrated; persistence artifacts were removed by snapshot restore and manual cleanup; no lateral movement detected.** Affected host returned to clean snapshot baseline within 7 hours of initial detection.

---

## 2. MITRE ATT&CK kill-chain mapping

| # | Time (UTC) | Tactic | Technique | Rule fired | Evidence index |
|---|---|---|---|---|---|
| 1 | 2026-06-25 10:34:11 | TA0003 Persistence | T1547.001 — Registry Run Keys | R3 `[VN-SOC R3] Registry Run Key Modification` | `.internal.alerts-security.alerts-default-000001` |
| 2 | 2026-06-25 10:38:35 | TA0002 Execution | T1059.001 — PowerShell EncodedCommand | R1 `[VN-SOC R1] PowerShell Encoded Command Execution` | `.internal.alerts-security.alerts-default-000001` |
| 3 | 2026-06-25 10:39:11 | TA0003 Persistence (reinforce) | T1547.001 — additional Run key | R3 (×3 alerts) | `.internal.alerts-security.alerts-default-000001` |
| 4 | 2026-06-25 10:52:02 | TA0006 Credential Access | T1110 — Brute Force | R4 `[VN-SOC R4] Multiple Failed Logon — Brute Force` | `.internal.alerts-security.alerts-default-000001` |
| 5* | 2026-06-25 16:20:23 | (FP) TA0006 Credential Access | T1003.001 — LSASS Memory | R2 `[VN-SOC R2] LSASS Memory Access` | (FP — see §6.2) |

\* Event #5 confirmed false positive from Microsoft Defender real-time scan. Documented for completeness; not part of attack chain.

---

## 3. Detailed timeline

### Event 1 — 10:34:11 UTC — Initial persistence (Registry Run key via `reg.exe`)

**Detection rule:** R3
**Source event:** Sysmon event_id 13 (registry_value_set)

```yaml
@timestamp     : 2026-06-25T10:34:11.660Z
host.name      : DESKTOP-L7FCMBQ
event.code     : 13
winlog.event_data.Image        : C:\Windows\system32\reg.exe
winlog.event_data.TargetObject : HKU\S-1-5-21-4188382834-1221911911-931124274-1000\
                                 SOFTWARE\Microsoft\Windows\CurrentVersion\Run\VNSOCSmokeTest
winlog.event_data.Details      : C:\Windows\System32\cmd.exe /c echo VNSOC_R3_smoke_test
winlog.event_data.User         : DESKTOP-L7FCMBQ\ADMIN
```

**Analyst note:** `reg.exe` from `system32` writing a HKCU Run key is suspicious in a workstation context. Legitimate software updates typically use `MsiExec.exe` or installer-named binaries, not `reg.exe` direct invocation. The Run key target invokes `cmd.exe /c echo ...` — placeholder payload in this lab, but pattern matches malware persistence stagers (real adversaries replace the echo with a downloader or loader).

**KQL to reproduce the event in Discover:**
```
event.code: "13" AND
winlog.event_data.Image: *\\reg.exe AND
winlog.event_data.TargetObject: *\\CurrentVersion\\Run\\*
```

### Event 2 — 10:38:35 UTC — PowerShell EncodedCommand execution

**Detection rule:** R1
**Source event:** Sysmon event_id 1 (process_creation)

```yaml
@timestamp     : 2026-06-25T10:38:35.661Z
host.name      : DESKTOP-L7FCMBQ
event.code     : 1
winlog.event_data.Image       : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
winlog.event_data.CommandLine : "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                                -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAVgBOAC0AUwBPAEMAIABSADEAIABzAG0Bbwbrai....
winlog.event_data.ParentImage : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
winlog.event_data.User        : DESKTOP-L7FCMBQ\ADMIN
winlog.event_data.ProcessGuid : {77b11330-03f7-6a3d-9104-000000000400}
winlog.event_data.Hashes      : MD5=BCF01E61144D6D6325650134823198B8,
                                SHA256=B4E7BC24BF3F5C3DA2EB6E9EC5EC10F90099DEFA91B820F2F3FC70DD...
```

**Decoded EncodedCommand (Base64 → UTF-16LE):**
```
Write-Host "VN-SOC R1 smoke test"
```

**Analyst note:** Decoded payload is benign in this lab event. However:
- The **technique** (use of `-EncodedCommand` to obscure intent) is identical to Emotet, TrickBot, Cobalt Strike loaders.
- Parent process is `powershell.exe` invoking another `powershell.exe` — uncommon pattern, often seen in macro-droppers that spawn powershell stagers.
- Hashes match Windows-shipped PowerShell binary (clean) — confirms it is the OS PowerShell, not a smuggled binary.

**Pivot opportunity:** investigate parent's parent (grandparent process) to determine HOW PowerShell was invoked. If parent was `winword.exe`, indicates **macro-dropper**; if `outlook.exe` or `chrome.exe`, indicates **phishing payload**. In this lab, manual launch from CLI.

### Event 3 — 10:39:11 UTC — Persistence reinforcement (×3 Run keys)

**Detection rule:** R3 (×3 alerts, all identical)
**Source event:** Sysmon event_id 13 (registry_value_set), 3 events within 12ms

```yaml
@timestamp     : 2026-06-25T10:39:11.833Z (and .840Z, .845Z)
host.name      : DESKTOP-L7FCMBQ
event.code     : 13
winlog.event_data.Image        : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
winlog.event_data.TargetObject : HKU\S-1-5-21-4188382834-1221911911-931124274-1000\
                                 SOFTWARE\Microsoft\Windows\CurrentVersion\Run\VnSocR3Test
winlog.event_data.Details      : powershell.exe -Command "Write-Host VN-SOC R3 test"
winlog.event_data.User         : DESKTOP-L7FCMBQ\ADMIN
```

**Analyst note:** 36 seconds after Event 2, **same user account ADMIN** wrote a second Run key — this time using `powershell.exe` directly (instead of `reg.exe` as in Event 1). The 3 near-instant alerts at .833 / .840 / .845 ms are likely from registry write batching by PowerShell ItemProperty cmdlet. The new Run key value invokes another PowerShell — chaining persistence to execution.

**Correlation with Event 1:** same user, same registry hive (HKU\…\Run), same target host. High confidence this is a **persistence reinforcement** by the same actor — common adversary technique to ensure foothold survives partial cleanup.

### Event 4 — 10:52:02 UTC — Brute force credential access

**Detection rule:** R4 (threshold rule)
**Source events:** Windows Security event_id 4625 (failed logon), 12 events within ~12 seconds

```yaml
@timestamp           : 2026-06-25T10:52:02.716Z
host.name            : DESKTOP-L7FCMBQ
event.code           : 4625
winlog.channel       : Security
winlog.event_data.TargetUserName : VnSocBruteTest
winlog.event_data.LogonType      : 3 (Network)
winlog.event_data.Status         : 0xC000006D (bad user/pass)
winlog.event_data.SubStatus      : 0xC000006A (wrong password)
```

**Analyst note:** 12 consecutive failed logons against username `VnSocBruteTest` (no such user exists locally — adversary trying common admin variants?). LogonType 3 = network logon — likely **SMB/IPC$ brute force** rather than interactive console. Source IP not captured by default Windows Security log; would require additional auditing (Audit Logon → Success+Failure).

**Hypothesis:** post-execution discovery phase where adversary attempts to lateral-move using common username dictionary.

### Event 5* (FP) — 16:20:23 UTC — Windows Defender LSASS scan

**Detection rule:** R2
**Source event:** Sysmon event_id 10 (process_access)

```yaml
@timestamp                  : 2026-06-25T16:20:23.724Z
event.code                  : 10
winlog.event_data.SourceImage   : C:\Program Files\Windows Defender\MsMpEng.exe
winlog.event_data.TargetImage   : C:\Windows\system32\lsass.exe
winlog.event_data.GrantedAccess : 0x1010 (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)
winlog.event_data.CallTrace     : ntdll.dll+9d524 |
                                  KERNELBASE.dll+308ee |
                                  mpengine.dll+1383ce (Defender module)
```

**Analyst note:** Source is `MsMpEng.exe` (Microsoft Malware Protection Engine — legitimate Windows Defender). Call trace includes `mpengine.dll` — confirms Defender's own scan engine. **Confirmed false positive.**

This event happened **5.5 hours after the main attack chain** — not part of incident chain. Including it here documents the FP for tuning purposes (see §6.2).

---

## 4. Indicators of Compromise (IoCs)

| Type | Value | Source event |
|---|---|---|
| Registry path | `HKU\S-1-5-21-4188382834-1221911911-931124274-1000\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\VNSOCSmokeTest` | Event 1 |
| Registry path | `HKU\…\Run\VnSocR3Test` | Event 3 |
| Process name | `powershell.exe -EncodedCommand <base64>` | Event 2 |
| ProcessGuid | `{77b11330-03f7-6a3d-9104-000000000400}` | Event 2 (unique to this execution) |
| User account | `DESKTOP-L7FCMBQ\ADMIN` | All events 1-4 |
| Brute-force target | `VnSocBruteTest` (fictitious account name) | Event 4 |
| Logon type | 3 (Network — SMB / NTLM relay candidate) | Event 4 |

**No file IoCs** — adversary did not drop binaries (used LOLBins `reg.exe`, `powershell.exe`, `cmd.exe`).
**No network IoCs** in this chain — no C2 callback observed (R5 alerts in same time window were all from `agy.exe`, legitimate AI agent — see [pha4-results.md Lesson 4](../pha4-results.md)).

---

## 5. Containment & response actions

| # | Time | Action | Result |
|---|---|---|---|
| 1 | 10:55 | SOC analyst reviewed R3 alerts in Kibana, confirmed Run keys created by ADMIN account | Confirmed persistence |
| 2 | 11:02 | Pivot to Sysmon e1 events for same ProcessGuid `{77b11330-03f7-6a3d-9104-...}` — found PowerShell parent chain | Confirmed execution context |
| 3 | 11:15 | Reviewed R4 brute force alert — confirmed external attempt against fake account (no real damage) | False target — no compromised account |
| 4 | (Pha 4 final) | VM Win10 snapshot restored to `pha4-framework-ready-2026-06-25` baseline | Persistence artifacts removed |
| 5 | Post-restore | Run `Get-ItemProperty HKCU:\…\Run\*` to verify no leftover keys | ✅ Clean |
| 6 | Post-restore | Run `Get-Service Sysmon64, winlogbeat` to verify telemetry still working | ✅ Both Running |

**Note on lab context:** in production, containment would also include:
- Network isolate host via firewall/EDR.
- Force-logout user, reset ADMIN password.
- Forensic disk image before snapshot restore (preserve evidence).
- Notify Information Security manager + affected business unit.

---

## 6. Root cause analysis

### 6.1 What allowed the attack chain to execute

1. **Admin-level account in regular use** — ADMIN user had unrestricted write access to HKCU Run keys + PowerShell execution. Best practice: separate admin account for elevation tasks only.
2. **No application control** — `powershell.exe -EncodedCommand` not blocked by AppLocker / WDAC. Best practice: restrict PowerShell to Constrained Language Mode for non-admin users.
3. **No source restriction on local logon attempts** — brute force could fire 6+ attempts before account lockout (no AccountLockoutPolicy set in lab). Production: 5-attempt lockout + monitoring.

### 6.2 Why R2 alert was a false positive

Microsoft Defender real-time protection scans LSASS memory as part of credential theft detection. This **legitimate AV scan** uses identical access mask (`0x1010` = `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`) that Mimikatz uses for credential dumping.

**Why this matters in production:**
- Cannot blindly exclude all Defender accesses — attackers can inject malicious code into MsMpEng process (`AV evasion via process hollowing`).
- Proper tuning requires: SourceImage path match + verify Microsoft signature + match call trace pattern (legit Defender always has `mpengine.dll` in call trace).

This FP is tracked in [`detection-rules/R2-T1003.001-lsass-access.md §4`](../detection-rules/R2-T1003.001-lsass-access.md) for Pha 5+ tuning.

---

## 7. Lessons learned

### 7.1 Detection coverage

- ✅ **3/4 chain phases detected with high signal** — R3 (persistence), R1 (execution), R4 (brute force) all fired within seconds of attack action.
- ⚠️ **No initial access detection** — adversary somehow obtained ADMIN credentials before this timeline. Recommend: add detection for unusual user logon patterns + privileged account use outside business hours.
- ⚠️ **No C2 detection (R5)** — adversary in this scenario did not establish callback (or did so via channels already whitelisted). Recommend: add Suricata network IDS to catch network-level beaconing that endpoint Sysmon may miss.

### 7.2 Process improvements

- **Time-to-detect (TTD) average:** ~30 seconds from event to alert in Kibana (excellent for lab; production realistic 1-3 minutes due to log shipping infrastructure).
- **False positive rate (R5 agy.exe + R2 MsMpEng):** without tuning, FP burden could overwhelm analyst capacity. Tuning workflow per [pha4-results.md §Lesson 4](../pha4-results.md) is essential before scaling to multiple endpoints.

### 7.3 Recommendations

| Priority | Recommendation | Mapped backlog |
|---|---|---|
| High | Add AppLocker / WDAC policy to block PowerShell `-EncodedCommand` for non-admin users | OS hardening |
| High | Implement account lockout policy (5 fails / 15 min) | OS hardening |
| Medium | Tune R2 — whitelist `MsMpEng.exe` SourceImage + verify signature | [R2 spec §4](../detection-rules/R2-T1003.001-lsass-access.md) |
| Medium | Add Suricata network IDS for network-layer detection | Pha 5+ expansion (network layer) |
| Low | Audit policy: enable Audit Logon Success+Failure subcategory for source IP capture in 4625 events | OS hardening |

---

## 8. Appendices

### A. Kibana KQL queries used during investigation

**Pivot 1 — Find all events from suspected ProcessGuid (process tree analysis):**
```
winlog.event_data.ProcessGuid: "{77b11330-03f7-6a3d-9104-000000000400}"
OR winlog.event_data.ParentProcessGuid: "{77b11330-03f7-6a3d-9104-000000000400}"
```

**Pivot 2 — All registry writes by ADMIN in time window:**
```
event.code: "13" AND
winlog.event_data.User: "DESKTOP-L7FCMBQ\\ADMIN" AND
@timestamp >= "2026-06-25T10:30:00Z" AND
@timestamp <= "2026-06-25T11:00:00Z"
```

**Pivot 3 — All process_creation events parented by PowerShell:**
```
event.code: "1" AND
winlog.event_data.ParentImage: *\\powershell.exe AND
winlog.event_data.User: "DESKTOP-L7FCMBQ\\ADMIN"
```

### B. Raw ES queries for evidence collection (cURL from VPS-side)

```bash
PASSWORD=$(grep '^password' ~/elastic-credentials.txt | cut -d= -f2 | tr -d ' ')

# All alerts for this incident (chronological)
curl -sk -u "elastic:$PASSWORD" \
  "https://localhost:9200/.internal.alerts-security.alerts-default-*/_search?size=20&sort=@timestamp:asc&pretty" \
  -H "Content-Type: application/json" \
  -d '{"query":{"range":{"@timestamp":{"gte":"2026-06-25T10:30:00Z","lte":"2026-06-25T11:00:00Z"}}}}'

# Specific alert detail (replace rule name)
curl -sk -u "elastic:$PASSWORD" \
  "https://localhost:9200/.internal.alerts-security.alerts-default-*/_search?size=1&pretty" \
  -H "Content-Type: application/json" \
  -d '{"query":{"match_phrase":{"kibana.alert.rule.name":"[VN-SOC R3] Registry Run Key Modification"}}}'

# Source event by ProcessGuid (for process tree)
curl -sk -u "elastic:$PASSWORD" \
  "https://localhost:9200/winlogbeat-*/_search?size=20&pretty" \
  -H "Content-Type: application/json" \
  -d '{"query":{"match_phrase":{"winlog.event_data.ProcessGuid":"{77b11330-03f7-6a3d-9104-000000000400}"}}}'
```

### C. MITRE ATT&CK Navigator export note

For visualization, this incident maps to ATT&CK Navigator layer JSON with:
- Tactics: `TA0002 Execution`, `TA0003 Persistence`, `TA0006 Credential Access`
- Techniques: `T1059.001`, `T1547.001`, `T1110`
- Detection score: 4/4 (all chained techniques detected by SIEM rules)

Export Kibana → Stack Management → Detection Rules → Bulk export NDJSON → upload via Navigator layer importer for heatmap view.

---

*This is **Incident Report VN-SOC-2026-0001**, the first formal incident in the VN-SOC Lab. Methodology and structure follow standard enterprise SOC incident response format (NIST 800-61 Rev2 IR Handler). Subsequent incidents will be numbered VN-SOC-2026-0002, etc.*

*— Reporter: gnid31, SOC Analyst T1, 2026-06-25*
