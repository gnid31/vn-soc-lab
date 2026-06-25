# VN-SOC Lab

> End-to-end Security Operations Center simulation for a Vietnamese banking / fintech-style environment.
> Built as a 2-week solo project to demonstrate practical skills for SOC / DFIR Intern and AI-in-Security Engineer Intern roles.

---

## What this repo contains

| File | Purpose |
|---|---|
| [`report.md`](report.md) | **Main deliverable** — describes only what has actually been built and verified. Updated incrementally as each phase ships. (Vietnamese) |
| [`roadmap.md`](roadmap.md) | Plans, design notes, and pending phases. Content graduates into `report.md` once executed. (Vietnamese) |
| [`CHANGELOG.md`](CHANGELOG.md) | Append-only log — one line per change, with timestamp + actor. |
| [`AGENTS.md`](AGENTS.md) | Working protocol for the two AI agents collaborating on this repo (Claude Code on Kali, Antigravity on Windows 10). |
| `configs/` | Production configuration files (Logstash pipeline, Winlogbeat YAML, Sysmon XML). |
| `detection-rules/` | Kibana detection rules — one Markdown explanation file plus the NDJSON export per rule. |
| `incidents/` | Incident Reports written against simulated attack chains (Phase 5). |

## Current status (high level)

- ✅ **Phase 1 — SIEM Backend.** Bare-metal Elasticsearch 8.19.17 + Kibana + Logstash on Ubuntu 24.04 VPS. UFW hardened, TLS internal, secrets stored chmod 600.
- 🔄 **Phase 2 — Endpoint Telemetry.** Sysmon (SwiftOnSecurity config) + Winlogbeat 8.x ship logs from Windows 10 victim to Logstash:5044.
- ⏳ Phase 3 — Detection Engineering (MITRE ATT&CK rules in Kibana).
- ⏳ Phase 4 — Adversary Emulation (Atomic Red Team).
- ⏳ Phase 5 — Incident Response & documentation.

See [`report.md`](report.md) for the full technical write-up (Vietnamese).

## Architecture (snapshot)

```
Windows 10 endpoint  ──Beats:5044──►  Logstash  ──HTTPS:9200──►  Elasticsearch  ◄──HTTPS:5601──  Kibana UI
   Sysmon + Winlogbeat                     │                         │
   Atomic Red Team (Phase 4)               └─── filter / enrich      └─── ECS v8 index winlogbeat-*

   Kali Linux (attacker)  ──LAN──►  Windows 10 victim                  Analyst (browser + SSH)
```

## Why this exists

Most SOC intern CVs list tutorial certifications and toy projects. This repo is the work itself — every commit corresponds to something actually deployed on a real VPS, an actual rule fired, an actual incident report written. The goal is to make hiring conversations concrete:

> "I deployed bare-metal Elastic 8.x with hardened defaults, built a Logstash pipeline that normalises Sysmon events to ECS v8, then wrote N detection rules mapped to MITRE ATT&CK and validated them with Atomic Red Team. Here is the commit history."

## Reproducibility — re-deploy the lab WITHOUT any AI tool

This repo is **AI-accelerated, not AI-dependent**. Every step has a manual command path that any SOC engineer can copy-paste into their own SSH / PowerShell terminal. AI agents (Claude Code on Kali, Antigravity on Win10) were used to drive automation faster during the original build — but the docs are written so a reader with no AI access can rebuild the lab in ~4 hours by:

1. Reading [`report.md`](report.md) section-by-section and pasting shell commands directly.
2. Following [`detection-rules/`](detection-rules/) specs (`§5 Kibana UI steps`, `§6 Smoke-test`) which are pure CLI / GUI instructions.
3. Skipping any block labelled "Antigravity prompt" or "AI prompt" — these are accelerators, not required steps. Equivalent manual commands are provided alongside.

The only artifact that is AI-workflow-specific is [`AGENTS.md`](AGENTS.md) (multi-agent git protocol) — solo human users can ignore it.

## License & access

Private repository. Access granted on a per-recruiter basis via GitHub invitation.

— *`gnid31`, Vietnam, 2026.*
