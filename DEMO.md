# VN-SOC Lab — Demo Script (60-90 second walkthrough)

> Live demo flow cho recruiter / interviewer: **1 single attack → end-to-end SOC pipeline observable**.
> Tool record gợi ý: **asciinema** (terminal, dễ nhúng GitHub) hoặc **OBS Studio** (full screen với browser).

---

## Pre-demo checklist (do once before recording)

```bash
# 1. All hosts on
ping -c 1 192.168.154.163 && ping -c 1 192.168.154.164 && ping -c 1 192.168.154.165
ssh vps 'docker ps | wc -l && systemctl is-active elasticsearch kibana logstash vnsoc-soar.timer'

# 2. Reset alert state for clean demo timeline
ssh vps 'sudo bash -c "echo {\"last_ts\":\"$(date -u +%FT%T.000Z)\"} > /var/lib/vnsoc-soar/state.json && chown namth:namth /var/lib/vnsoc-soar/state.json"'

# 3. Open 4 browser tabs (use Firefox profile for clean state)
#    Tab 1: http://43.228.215.234:5601/app/security/alerts            (Kibana)
#    Tab 2: http://192.168.154.165:9000/                               (TheHive)
#    Tab 3: http://192.168.154.163:9001/                               (Cortex)
#    Tab 4: http://127.0.0.1:5678/workflows                            (n8n)
```

---

## Recording — 60-90 second flow

### Frame 1 (0-10s) — Set scene

**Terminal:**
```bash
echo "🎯 VN-SOC Lab — single attack → full SOC pipeline demo"
echo "📍 Attacker: Kali 192.168.154.151"
echo "🎯 Target: DVWA on SOC-Tools 192.168.154.165:8080"
```

### Frame 2 (10-20s) — Fire attack

**Terminal:**
```bash
# Single LFI attack — known-bad pattern
curl -s -o /dev/null -w "→ HTTP %{http_code}\n" \
  "http://192.168.154.165:8080/vulnerabilities/fi/?page=../../../../etc/passwd"
echo "✅ Attack sent. Waiting for SOC pipeline..."
```

### Frame 3 (20-40s) — Show Kibana alert fire

**Browser → Tab 1 (Kibana → Security → Alerts):**
- Filter: `kibana.alert.rule.name : "*VN-SOC*"`
- Range: last 5 minutes
- Refresh every 5s
- **Annotate (overlay text):** "R9 (ML) + R8 (file probe) fired automatically — based on Logstash inline ML enrichment + KQL rules"

### Frame 4 (40-55s) — TheHive case auto-created

**Browser → Tab 2 (TheHive → Cases):**
- Latest case appears (#N+1) within 30 seconds of alert
- Click case → show:
  - Title contains rule name
  - Severity HIGH (from R9)
  - Tags `vn-soc-lab` + `auto-created`
  - **Observables tab:** URL + IP auto-extracted from alert payload
- **Annotate:** "Case auto-created by n8n workflow (systemd timer poll → webhook)"

### Frame 5 (55-75s) — Cortex enrichment

**Browser → Tab 2 (TheHive case → Observables):**
- Click on IP observable `192.168.154.151`
- Show **Reports tab** — already populated by Cortex auto-run
- AbuseIPDB taxonomy displayed
- (Optional) Click on URL observable → VirusTotal report

**Annotate:** "Cortex analyzers ran automatically — VirusTotal for URL, AbuseIPDB for IP"

### Frame 6 (75-90s) — Wrap up

**Terminal split / overlay:**
```bash
echo
echo "🏁 Demo complete — pipeline timing:"
echo "    Attack fired           → Kibana alert     :  ~30s (rule schedule 1min)"
echo "    Alert in ES            → TheHive case     :  ~30s (systemd timer)"
echo "    Case created           → Cortex enriched  :  ~15s (analyzer container)"
echo "    Total end-to-end SOC ops loop             :  ~60-90s"
echo
echo "🛠  9 detection rules (R1-R9) covering 9 MITRE techniques"
echo "🤖 ML-based URL classifier (Pha 8) — TF-IDF + LogReg"
echo "📦 2 SIEMs parallel (Elastic + Wazuh) — multi-stack pattern"
echo "🔗 Full code at github.com/gnid31/vn-soc-lab"
```

---

## Tooling — choose 1 of 2

### Option A: asciinema (terminal-only, lightweight, ~200 KB)

```bash
sudo apt install -y asciinema
asciinema rec demo.cast \
  --title "VN-SOC Lab — single attack end-to-end SOC pipeline" \
  --idle-time-limit 2
# follow the script above; type slowly
# Ctrl+D to stop
asciinema upload demo.cast   # uploads to asciinema.org → public link
# OR convert to GIF:
sudo apt install -y agg
agg demo.cast demo.gif       # standalone GIF
```

Embed in README:
```markdown
[![asciicast](https://asciinema.org/a/<ID>.svg)](https://asciinema.org/a/<ID>)
```

### Option B: OBS Studio (full screen with browser, professional)

```bash
sudo apt install -y obs-studio
obs &
```

Settings:
- Resolution: 1920x1080
- 30 FPS
- Output: MP4 (H.264)
- Source: capture display

After record:
- Trim with `ffmpeg -i demo.mp4 -ss 00:00:00 -to 00:01:30 -c copy demo-trim.mp4`
- (Optional) convert to GIF: `ffmpeg -i demo-trim.mp4 -vf "fps=10,scale=1024:-1" demo.gif`
- Upload to YouTube unlisted → embed link in README

---

## Verify the demo worked (post-recording sanity check)

```bash
# Confirm: alert in ES
ssh vps 'curl -sk -u elastic:<PWD> "https://localhost:9200/.internal.alerts-security.alerts-default-000001/_count?q=kibana.alert.rule.name:%22*VN-SOC*%22"'

# Confirm: TheHive case auto-created
sshpass -p '1' ssh gnid@192.168.154.165 \
  'curl -s -X POST "http://127.0.0.1:9000/api/v1/query?name=count" \
    -H "Authorization: Bearer <THEHIVE_KEY>" \
    -H "Content-Type: application/json" \
    -d "{\"query\":[{\"_name\":\"listCase\"}]}"'

# Confirm: Cortex job ran successfully
sshpass -p '1' ssh gnid@192.168.154.163 \
  'curl -s -H "Authorization: Bearer <CORTEX_KEY>" \
    "http://127.0.0.1:9001/api/job?range=0-5"' | python3 -m json.tool | head -20
```

---

## Post-demo polish (optional)

- Add caption overlay text in OBS (Source → Text) — call out timing milestones.
- Add background music: free royalty-free track ([Bensound](https://www.bensound.com/) Cinematic).
- Trim dead time between frames (no waiting on screen — pre-load tabs).
- 2x speed-up parts khi rule còn đợi schedule (Kibana 1min loop).

---

## Final embedded asset paths

After recording, place artifacts:

```
.
├── DEMO.md                    ← this file (recording script)
├── demo.cast                  ← asciinema cast (or)
├── demo.mp4                   ← OBS screen record (or)
└── demo.gif                   ← compressed for inline README embed
```

Then update `README.md` top section to embed:

```markdown
## Quick demo

![60-second SOC pipeline demo](demo.gif)

Or full asciinema: <https://asciinema.org/a/XXXXX>
```
