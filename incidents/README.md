# Incidents — VN-SOC Lab

Sample incident reports produced from VN-SOC Lab detection alerts.

## Naming convention

```
VN-SOC-YYYY-NNNN-<short-slug>.md
```

- `YYYY` — year (2026 for this lab).
- `NNNN` — 4-digit sequence number (0001, 0002, ...).
- `short-slug` — kebab-case 1–3 word descriptor of the incident type.

## Current incidents

| ID | Title | Severity | Status | Date |
|---|---|---|---|---|
| [VN-SOC-2026-0001](VN-SOC-2026-0001-killchain.md) | Adversary kill-chain attempt — Persistence → Execution → Brute Force | High | Contained | 2026-06-25 |

## Template

[`template-incident-report.md`](template-incident-report.md) — blank skeleton following NIST 800-61 Rev2 incident handler format. Copy and rename when starting a new incident write-up.

## Workflow

1. Detect — Kibana → Security → Alerts triggers analyst review.
2. Pivot — Use KQL queries in Discover to enrich context (process tree, parent chain, user activity).
3. Document — copy template, fill in evidence with **real cURL / KQL outputs**.
4. Contain — execute response actions, log each step with timestamp.
5. Close — root cause + lessons learned + recommendations → backlog items.
6. Commit — incident file + any rule tuning that came out of analysis.

## Evidence reference standard

Each event in an incident report MUST cite:
- **Source ES index** — `winlogbeat-YYYY.MM.dd` or `.internal.alerts-security.alerts-default-*`
- **@timestamp** — exact ISO8601 UTC time
- **Key field values** — verbatim from `_source` (not paraphrased)
- **Pivot KQL** — query that another analyst can run to reproduce

Without these, the report is opinion, not evidence.
