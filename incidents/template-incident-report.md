# INCIDENT REPORT — VN-SOC-YYYY-NNNN

> *One-line summary of incident — what happened, where, when (high level)*

---

## Incident metadata

| Field | Value |
|---|---|
| Incident ID | `VN-SOC-YYYY-NNNN` (year-sequence) |
| Severity | Low / Medium / High / Critical |
| Status | Detected / Triaging / Contained / Eradicated / Closed |
| Date detected | YYYY-MM-DD HH:MM UTC |
| Date contained | YYYY-MM-DD HH:MM UTC |
| Reporter | <username>, <role> |
| Affected host(s) | <hostname>, <OS>, <user> |
| Detection source | <SIEM rule IDs that fired> |
| Containment lead | <username> |

---

## 1. Executive summary

*3–5 sentences in business language. What happened, when, scope, current status, business impact (if any).*

**Recommended template:**
> On `<date>`, between `<start_time>` and `<end_time>`, host `<hostname>` exhibited `<N>` indicators matching `<adversary tactic>` from MITRE ATT&CK framework. Initial detection was triggered by `<rule_id>`. Investigation revealed `<key finding>`. Containment actions included `<actions taken>`. **No `<data type>` confirmed exfiltrated.** Affected host returned to clean state by `<containment_time>`.

---

## 2. MITRE ATT&CK kill-chain mapping

| # | Time (UTC) | Tactic | Technique | Rule fired | Evidence index |
|---|---|---|---|---|---|
| 1 | YYYY-MM-DD HH:MM:SS | TA00NN <Name> | TNNNN.NNN — <Name> | <Rule ID> | `<ES index>` |
| 2 | ... | ... | ... | ... | ... |

---

## 3. Detailed timeline

### Event N — HH:MM:SS UTC — <Description>

**Detection rule:** <Rule ID>
**Source event:** Sysmon event_id N (name) / Security event_id NNNN

```yaml
@timestamp: ...
host.name : ...
event.code: ...
winlog.event_data.<field>: <value>
...
```

**Analyst note:** *Explain WHY this is suspicious, WHAT pattern this matches in TTPs, and WHAT pivot would refine attribution.*

**Pivot opportunity:** *Suggested next query in Kibana Discover or KQL pivot.*

---

## 4. Indicators of Compromise (IoCs)

| Type | Value | Source event |
|---|---|---|
| File hash (SHA256) | ... | Event N |
| File path | ... | Event N |
| Registry path | ... | Event N |
| Process name + command line | ... | Event N |
| Network destination (IP/domain) | ... | Event N |
| User account | ... | Event N |
| Logon type | ... | Event N |

---

## 5. Containment & response actions

| # | Time | Action | Result |
|---|---|---|---|
| 1 | HH:MM | <Action taken> | <Outcome> |
| 2 | HH:MM | <Action taken> | <Outcome> |

**Production checklist (add when applicable):**
- [ ] Network isolate host via firewall/EDR
- [ ] Force-logout affected user, reset password
- [ ] Forensic disk image (preserve evidence) before remediation
- [ ] Notify InfoSec manager + affected business unit
- [ ] Update threat intelligence with new IoCs
- [ ] Post-incident review meeting scheduled

---

## 6. Root cause analysis

### 6.1 What allowed the attack chain to execute / progress

*Bullet list of preconditions / vulnerabilities / misconfigurations that enabled the incident.*

### 6.2 False positives observed (if any)

*Document FP events alongside true positives — important for tuning.*

---

## 7. Lessons learned

### 7.1 Detection coverage

- ✅ What worked.
- ⚠️ What partially worked.
- ❌ What missed.

### 7.2 Process improvements

*Time-to-detect, time-to-contain, FP rate impact on analyst workload.*

### 7.3 Recommendations

| Priority | Recommendation | Backlog ticket |
|---|---|---|
| High | ... | <ref> |
| Medium | ... | <ref> |
| Low | ... | <ref> |

---

## 8. Appendices

### A. Kibana KQL queries used during investigation

```
<KQL pivot 1>
```

### B. Raw ES queries (cURL from VPS-side)

```bash
PASSWORD=$(grep '^password' ~/elastic-credentials.txt | cut -d= -f2 | tr -d ' ')

# Investigation query
curl -sk -u "elastic:$PASSWORD" \
  "https://localhost:9200/<index>/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '<query>'
```

### C. Related references

- Detection rule specs: `detection-rules/R<N>-*.md`
- Phase reports: `report.md`, `pha4-results.md`
- Adjacent incidents: `incidents/VN-SOC-YYYY-NNNN-*.md`

---

*— Reporter: `<username>`, `<role>`, `<date>`*

---

## Usage notes (delete before publishing)

1. Replace all `<placeholder>` text and `YYYY-NNNN` IDs.
2. Sections 3.X — copy and replicate per detected event.
3. Section 4 IoCs — extract from raw event JSON.
4. Section 6 — be specific about WHY, not just WHAT.
5. Section 7 — recommendations should map to actionable backlog items.
6. Section 8 — include actual KQL/cURL used so report is reproducible by another analyst.
