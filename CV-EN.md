# VN-SOC Lab — CV (English, 1-page A4)

> Skills + Project section only. Format: category-per-line, comma-separated items — matches template provided (Programming / ML Frameworks / AI Fields / Tools).

---

## SKILLS

**Programming:** Python, Bash, KQL, EQL, Painless, YAML, Sigma, PowerShell

**SIEM & Monitoring:** Elasticsearch 8.19, Kibana, Logstash, Wazuh 4.9, Filebeat, Winlogbeat, ILM policy, saved objects, runtime fields

**Detection Engineering:** MITRE ATT&CK mapping, Sigma YAML (portable KQL/EQL/Splunk/Sentinel), threshold/EQL sequence/new_terms/indicator match rules, false-positive tuning

**Endpoint & Network Security:** Sysmon (SwiftOnSecurity + custom RuleGroup), FIM (Wazuh syscheck), Suricata NIDS, Zeek, ET Open ruleset, Atomic Red Team

**Threat Intelligence & SOAR:** TheHive 5, Cortex 3, n8n workflow, VirusTotal API, AbuseIPDB, URLhaus IOC feed, cross-network SSH tunneling

**ML / Analytics:** Scikit-learn (TF-IDF + LogisticRegression), Flask + gunicorn, UEBA z-score baseline, dataset synthesis + FP tuning

**Malware & Deception:** YARA rule authoring (ELF/PE magic FP mitigation), Cowrie SSH honeypot, IOC feed integration

**Vulnerability Management:** Trivy (Docker + FS CVE + SBOM), Nikto web scanning, continuous vuln pipeline

**DevOps / Ops:** Docker Compose (multi-stage, host network, volume binds), systemd services + timers, UFW, TLS/PKI self-signed, sysctl tuning, autossh reverse tunnels

**Cloud & Infrastructure:** Ubuntu VPS ops, LVM, ES cluster tuning, disk expand `growpart`, RAM/heap sizing

**Documentation & Reporting:** NIST 800-61 Rev2 IR reports, dual-path GUI + CLI walkthroughs, deploy-then-document protocol, Markdown/Mermaid technical writing

**Tools:** Git, GitHub, Linux (Ubuntu, Kali), VMware Workstation, VS Code, Postman/curl, jq, Portainer

---

## WORK EXPERIENCE / PROJECT

### VN-SOC Lab — End-to-End Security Operations Center Simulation

**06/2026 – 07/2026 (~2.5 weeks solo)** · GitHub: `gnid31/vn-soc-lab`

*End-to-end SOC lab covering detection engineering, adversary emulation, incident response, ML detection, SOAR automation, FIM, honeypot, UEBA, and vulnerability management — deployed across 1 VPS + 4 VMs.*

**Key achievements:**

- Deployed hardened **Elasticsearch 8.19 + Kibana + Logstash** stack (VPS) and **Wazuh 4.9 HIDS full stack** (VM) for dual-SIEM coexistence with 10 log source indices; hardened TLS internal, UFW least-privilege, encryption keys keystore.

- Authored **18 detection rules (R1-R18)** in Kibana Detection Engine covering **19 MITRE ATT&CK techniques** across 4/5 rule types (query, threshold, EQL sequence multi-stage attack chain, new_terms baseline drift, indicator match); Sigma YAML for cross-SIEM portability via `sigma-cli` (Lucene / EQL / ES|QL / Splunk SPL / Sentinel KQL).

- Built **ML-based URL malicious classifier** (Scikit-learn TF-IDF + LogisticRegression, ~460-URL dataset), served via **Flask + gunicorn Docker multi-stage**; Logstash `http` filter inline-enriches every DVWA request with ML score/label (R9 fired 9 alerts 100% TP).

- Implemented **SOAR automation** (TheHive 5 + n8n + Cortex 3): systemd timer alert bridge (workaround for Kibana Basic license `.webhook` limit) → n8n workflow auto-extracts observables (URL/IP/UA) → TheHive case → Cortex analyzer (VirusTotal + AbuseIPDB) auto-enrichment; **detect → case → enriched in ~60-90 seconds** end-to-end (34 cases auto-created during smoke-test).

- Deployed **File Integrity Monitoring** (Wazuh syscheck on Windows 10 endpoint: 4 directories realtime + 5 registry keys) with 7 custom Wazuh Manager rules; Filebeat ships alerts to Elasticsearch for unified dual-SIEM Kibana view.

- Added **YARA malware detection** (9 rules with ELF/PE magic-byte FP mitigation, 177→0 false positives), **Cowrie SSH honeypot** (public port 2222, captured attacker sessions + commands), **UEBA behavioral analytics** (Python z-score baseline over 14-day rolling window, 6 metrics), and **Trivy + Nikto vulnerability scanning** on systemd daily/weekly timers (768 CVE findings first scan).

- Wrote **~5000 lines of Vietnamese dual-path documentation** (GUI-preferred + CLI equivalent) across MASTER-GUIDE + report + 11 phase docs + 18 detection rule specs + Sigma YAML library — ensuring full reproducibility (~8-hour manual redeploy without AI agent).

**Skills demonstrated:** Detection engineering, Sigma rule authoring, ML for security, SOAR automation, FIM, threat intel enrichment, honeypot deception, UEBA analytics, vulnerability management, cross-network SSH tunneling, Docker orchestration, multi-vendor SIEM integration, technical writing.

---

## Additional (optional line if space allows)

**Interests:** Open-source security tooling, detection engineering blogs (Elastic Security Labs, SigmaHQ, MITRE ATT&CK evaluations), CTF competitions (Forensics + Blue Team categories).
