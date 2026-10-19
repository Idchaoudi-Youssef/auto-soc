# EVERYTHING YOU NEED TO KNOW (give this file to the AI)

> **Audience: an AI assistant (Claude or similar) that knows NOTHING about this project except the files of this repository.**
> A human wants to deploy, understand, debug or rebuild this project and will talk to you. This file is your complete briefing.
> Read it entirely before answering. It is long on purpose.

---

## 0. How you must behave

1. **Never invent.** Every fact below carries an evidence tag:
   - `[REPO]` = verified in a file of this repository.
   - `[NOTES]` = from the author's own written notes/context (older than the final code; the repo wins on any conflict).
   - `[INFERRED]` = deduced by the previous AI; plausible but unverified. Say so when you rely on it.
   - `[UNKNOWN]` = the original file/value is lost. **Ask the user** or rebuild it and clearly label it "reconstructed".
2. **Some files are deliberately not in this repo** (the author could not or did not want to publish them). Section 9 tells you exactly which, and gives recipes to recreate them. When you recreate one, say it is a reconstruction, not the author's original.
3. **Secrets:** the repo contains only placeholders (`<GROQ_API_KEY>` etc., inventory in section 7). Never ask the user to paste real keys into the chat. If the user pastes one by accident, tell them to rotate it.
4. **Guide step by step.** Give one step, a command to verify it, and the expected output. Ask for the output before moving on. Prefer commands that print results over screenshots.
5. **Language:** reply in the user's language. A deployer may write in any language. Technical terms stay in English.
6. **Be honest about limits.** This is a lab project, not production software. Do not oversell it. Thresholds were chosen empirically, not mathematically derived.
7. This is a **defensive** project (detection and response). Helping deploy and test it on the user's own lab network is fine. Do not repurpose the test scenarios against systems the user does not own.

---

## 1. The project in one paragraph

An **automated SOC/SOAR platform** . A Wazuh SIEM raises an alert, which is sent by webhook to Shuffle (SOAR). Shuffle classifies it with a custom **Score API**, enriches IPs/file hashes with **VirusTotal** and **OTX AlienVault**, computes a NIST-inspired 0-100 severity score, then asks an **LLM (Groq, Llama 3.3 70B)** whether automatic action is safe. If the AI is confident, Shuffle automatically **blocks the IP** or **quarantines the file** on the Windows endpoint through Wazuh Active Response. If not, or for "suspicious behaviour" alerts, the alert goes to a **Flask analyst dashboard** where a human approves or rejects; approval is sent back to Shuffle, which then executes the response. Every alert is also created in **TheHive**, and notifications go to **Discord**.

---

## 2. Repository map

```text
auto_soc/
├── README.md                                   (public README, written by the user)
├── everythingunee2know-giveittoai.md           (THIS FILE)
├── .gitignore                                  (ignores .env, *.db, logs, nohup.out, *.exe, *.tar.gz, build/dist/spec)
├── .env.example                                (names of the keys used in Shuffle nodes; values are placeholders)
│
├── 1-windows-agent/                            # Windows host, Wazuh agent
│   └── quarantine.py                           [REPO] Active-response script (quarantine by SHA256). Compiled to quarantine.exe.
│
├── 2-wazuh-manager/                            # VM3 "wazuh-siem" 192.168.56.10
│   ├── events-api/events-api.py                [REPO] HTTP API exposing recent Wazuh alerts (port 8888)
│   ├── local_rules.xml                         EMPTY placeholder (custom rules, e.g. 100203) -> section 9
│   └── ossec-custom-blocks.conf                EMPTY placeholder (integration block etc.)     -> section 9
│
├── 3-shuffle-soar/                             # VM4 "shuffle-soar" 192.168.56.11
│   ├── workflows/SOC-Generic-Pipeline.json     [REPO] The whole Shuffle workflow (21 nodes, 2 webhook triggers). Secrets replaced by placeholders, icons removed.
│   └── ai-nodes/
│       ├── ai_fp_check.py                      [REPO] Code of the Shuffle node "AI_FP_Check" (copy of what is inside the JSON)
│       └── ai_chain_analysis.py                [REPO] Code of the Shuffle node "AI_Chain_Analysis" (copy of what is inside the JSON)
│
├── 4-score-api-and-dashboard/                  # VM5 "vm5" 192.168.56.12
│   ├── score-api/score.py                      [REPO] Router + scoring API (port 9999), Python stdlib only
│   ├── dashboard/                              [REPO] Flask + SQLite analyst dashboard (port 8080)
│   │   ├── app.py, requirements.txt, .env.example
│   │   ├── templates/ (base, index, alert_detail, login .html)
│   │   └── static/style.css
│   ├── thehive-cortex/docker-compose.yml       [REPO] Elasticsearch + TheHive + Cortex containers
│   └── legacy-decision-api/                    [REPO] decision_api.py + dashboard.html. EARLIER PROTOTYPE (port 9998, in-memory). NOT used by the final workflow. Ignore unless the user asks.
│
└── docs/                                       empty placeholders (screenshots, diagram, report PDF)
```

Notes:
- The `create_alert` node (Python, creates the TheHive alert on the automatic path) exists **only inside the workflow JSON**; there is no separate file for it. `[REPO]`
- No `.service` files, no Windows agent config, no Wazuh manager config, no TheHive `application.conf`, no Shuffle deployment files, and no test scripts are in the repo. See section 9.

---

## 3. Infrastructure

Isolated **host-only network `192.168.56.0/24`** (VirtualBox), fixed IPs. `[NOTES]` The author reports **five VirtualBox VMs in total** `[NOTES]`; only the machines below are documented. The roles of the other two (e.g. an attacker VM) are `[UNKNOWN]`: ask.

| Machine | Role | IP | OS user / paths |
|---|---|---|---|
| Windows host | Wazuh **agent**, **agent ID `002`**, test endpoint | `192.168.56.1` | monitored folder set in `SCAN_DIRS` (`C:\Users\<user>\Downloads`) |
| VM3 `wazuh-siem` | Wazuh **manager** 4.14.4 + **Events API** | `192.168.56.10` | Linux user `ubuntu22`; `/home/ubuntu22/events-api.py` |
| VM4 `shuffle-soar` | **Shuffle** SOAR (Docker Swarm) | `192.168.56.11` | |
| VM5 `vm5` | **TheHive 5 + Cortex + Elasticsearch** (docker), **Score API**, **Dashboard** | `192.168.56.12` | Linux user `ubuntu22`; `~/score-api/`, `~/soc-dashboard/`, `~/soc-lab/` (docker compose + config + data) |

| Service | Address | Notes |
|---|---|---|
| Wazuh API | `https://192.168.56.10:55000` | self-signed TLS; token via `POST /security/user/authenticate?raw=true` with Basic auth |
| Events API | `http://192.168.56.10:8888` | `/health`, `/agent/<id>/recent`, `/recent` |
| Shuffle UI / hooks | `http://192.168.56.11:3001` | webhook URLs look like `http://192.168.56.11:3001/api/v1/hooks/webhook_<id>` |
| Shuffle backend | `192.168.56.11:5001` | |
| TheHive | `http://192.168.56.12:9000` | alert API: `/api/alert` |
| Cortex | `http://192.168.56.12:9001` | deployed, but **no workflow node calls Cortex** `[REPO]` |
| Elasticsearch | `192.168.56.12:9200` | used by TheHive |
| Score API | `http://192.168.56.12:9999` | `/health`, `/classify`, `/` |
| Dashboard | `http://192.168.56.12:8080` | login required for UI |
| (legacy) Decision API | `:9998` | prototype, unused |

External services: VirusTotal API v3, OTX AlienVault API, Groq API (`llama-3.3-70b-versatile`), Discord webhook. The lab VMs need internet for these.

---

## 4. End-to-end flow

### 4.1 Common entry
```text
Wazuh alert (rule fires)
  -> Wazuh <integration> (shuffle) POSTs the alert JSON to the Shuffle webhook "Wazuh_Webhook"
  -> node Routeur: POST http://192.168.56.12:9999/classify  {"rule_id": "<id>"}
  -> returns {"type", "playbook", "rule_id"}; playbook is one of: block_ip | isolate_agent | analyst_review | log_only
```
`log_only` has no outgoing edge: the workflow simply stops. `[REPO]`

The Shuffle variables used everywhere (`$exec.all_fields.rule.id`, `$exec.all_fields.data.srcip`, `$exec.all_fields.syscheck.sha256_after`, `$exec.rule_id`, `$exec.title`) match the payload format of Wazuh's built-in Shuffle integration (fields `all_fields`, `title`, `rule_id`...). `[INFERRED]`

### 4.2 Playbook `block_ip` (brute-force)
```text
Routeur -> Get_VT_IP -> Get_OTX_IP -> Calc_Score -> AI_FP_Check
AI_FP_Check -> Discord_Notify                       (always)
AI_FP_Check -> create_alert (TheHive alert, Python) (always)
create_alert -> Get_Wazuh_Token -> Block_IP         ONLY IF likely_false_positive == false AND action_confidence > 75 AND decision == allow_auto_action
create_alert -> Send_To_Dashboard_FP                IF action_confidence < 76
```

### 4.3 Playbook `isolate_agent` (malware / file integrity)
Same as 4.2 but `Get_VT_HASH -> Get_OTX_HASH` instead of the IP lookups, and the response is `Get_Wazuh_Token -> Quarantine_File`.

### 4.4 Playbook `analyst_review` (suspicious behaviour, never automatic)
```text
Routeur -> AI_Chain_Analysis -> Create_Alert_copy (TheHive) -> Discord_Notify_copy -> Send_To_Dashboard_Analyst
```
`Calc_Score` and `AI_FP_Check` are NOT used here. No automatic response.

### 4.5 Human approval loop
```text
Analyst opens http://192.168.56.12:8080 -> alert detail -> clicks a decision
Dashboard POST SHUFFLE_APPROVAL_WEBHOOK  (trigger "Dashboard_Decision_Webhook")
  payload: {"dashboard_alert_id","decision","agent_id","srcip","sha256","playbook","comment"}
Shuffle: Get_Wazuh_Token_copy, then by $exec.decision:
   approve_block_ip   -> Block_IP_copy      (!netsh, srcip = $exec.srcip)
   approve_quarantine -> Quarantine_File_copy (!quarantine, sha256 = $exec.sha256)
   isolate_agent      -> Isolate_Agent      (!isolate)
   reject / mark_investigating -> nothing sent to Shuffle (dashboard status only)
```
`[REPO]` (app.py `make_decision`, workflow edges).

---

## 5. Component reference

### 5.1 Score API: `4-score-api-and-dashboard/score-api/score.py` `[REPO]`
- Python stdlib `http.server`, **not Flask**, no dependencies, port **9999**, logs via `logging`.
- `GET /health` -> `{"status":"ok","service":"score-api","port":9999}`
- `POST /classify` body `{"rule_id": "5712"}` -> `{"type","playbook","rule_id"}`
- `POST /` body = fields built by node `Calc_Score` (`level`, `firedtimes`, `tactic`, `description`, `agent`, `rule_id`, `srcip`, `playbook`, `vt_malicious_ip`, `vt_malicious_hash`, `otx_pulses_ip`, `otx_pulses_hash`) -> `{"score","severity","thehive_severity","recommended_action","evidence_report","details":{wazuh,vt,otx,mitre,freq,bonus}}`
- For `playbook == "isolate_agent"` it uses the **hash** VT/OTX values; otherwise the **IP** values.

**Router rule lists (deployed version):**

| Playbook | Rule IDs |
|---|---|
| `block_ip` (type bruteforce) | 5712, 5763, 5710, 5716, 100203, 40111 |
| `isolate_agent` (type malware) | 553, 550, 554, 510, 511, 512 |
| `analyst_review` (type suspicious) | 60109, 60110, 60111, 60112, 60160, 60106, 60154, 60170, 5402, 5403, 40101, 92031, 92027, 92066, 92205, 92213 |
| anything else | `log_only` |

**Scoring: 5 criteria x up to 20 points + bonus, capped at 100.**

| Criterion | 20 | 15 | 10 | 8 | 5 | 0 |
|---|---|---|---|---|---|---|
| Wazuh rule level | >=13 | 9-12 | 5-8 | | 1-4 | 0 |
| VirusTotal malicious engines | >20 | 6-20 | | 1-5 | | 0 |
| OTX pulse count | >5 | 3-5 | | 1-2 | | 0 |
| MITRE tactic keyword | privilege / impact / exfiltration | credential / execution / command / control | persistence / lateral / defense evasion | | reconnaissance / discovery / resource / initial access | unknown |
| Frequency (`firedtimes`) | >20 | 11-20 | 6-10 | | 3-5 | <3 |

Bonus **+5** if at least 3 criteria are >=15. Severity: **>=75 critical, >=50 high, >=25 medium, else low**. TheHive severity: low 1, medium 2, high 3, critical 4. Recommended action text: critical "BLOCK IP for 6 hours + Urgent alert to SOC team", high "BLOCK IP for 1 hour + Notify analyst", medium "Email analyst for review", low "Info ticket only - no action required" (text only; actual block duration is not implemented in Shuffle).

Start/restart: `pkill -f score.py; sleep 2; nohup python3 ~/score-api/score.py &` `[NOTES]`

### 5.2 Events API: `2-wazuh-manager/events-api/events-api.py` `[REPO]`
- Stdlib `http.server`, port **8888**, runs on the Wazuh manager VM; reads the last ~2 MB of `/var/ossec/logs/alerts/alerts.json` (so it must be able to read that file).
- `GET /health`; `GET /agent/<agent_id>/recent?limit=10&min_level=5&suspicious_only=true`; `GET /recent?limit=15`.
- "Suspicious" = rule in `INTERESTING_RULES` (60109-60112, 60106, 60107, 5712, 5763, 5710, 5716, 553, 550, 554, 510, 511, 5402, 5403, 60125, 60145, 92057, 40101) **or** the alert has a MITRE tactic.
- Returns per alert: timestamp, rule_id, rule_level, description, mitre_tactic, mitre_technique, agent, srcip, eventdata, eventID.
- Used only by `AI_Chain_Analysis`. Deployed as a systemd service `events-api`, log `/var/log/events-api.log`. `[NOTES]` (unit file not in repo, see 9.6)

### 5.3 AI nodes (Shuffle "Execute Python"), model `llama-3.3-70b-versatile` via Groq `[REPO]`
Prompts are written in French. Values like `"$calc_score.body.score"` are **Shuffle variable substitutions done before the code runs**, so the node labels must keep exactly these names (Shuffle lower-cases them): `Calc_Score`, `Routeur`, `AI_FP_Check`, `AI_Chain_Analysis`.

**AI_FP_Check** (playbooks block_ip / isolate_agent). Input: score, severity, recommended action, agent, rule, level, firedtimes, srcip, VT/OTX/Wazuh/frequency details. Output JSON:
`likely_false_positive, fp_confidence (0-100), action_confidence (0-100), decision (allow_auto_action | block_auto_action), reason, analyst_note, recommended_action, status, error`.
Node-side safety rules (applied in code after the AI answers): `fp_confidence > 60` -> false positive + block; `action_confidence <= 74` -> block; `likely_false_positive` -> block. **If Groq fails or errors, the node fails safe: decision = block_auto_action** (no automatic action), fp_confidence 100, action_confidence 0. Temperature 0.2.

**AI_Chain_Analysis** (playbook analyst_review). Fetches the last 10 suspicious events of the agent from the Events API, asks the LLM to correlate them. Output: `ai_analysis{chain_detected, attack_pattern, events_correlated, summary (French), threat_level (LOW|MEDIUM|HIGH|CRITICAL), confidence_percent, is_likely_false_positive, recommended_actions[], mitre_tactics_observed[], analyst_priority (P1..P3), events_detail[{timestamp, rule_id, description, mitre_tactic, mitre_technique, user, significance}]}`, `thehive_severity` (LOW 1 .. CRITICAL 4), `timeline`, `error`, `status`. Has fallbacks if Events API or Groq fail. Temperature 0.3. It computes its **own** severity, independent from the Score API.

The AI thresholds (60 / 74-75) were chosen empirically; "calibration on real data" is the honest stated future work.

### 5.4 Shuffle workflow: `3-shuffle-soar/workflows/SOC-Generic-Pipeline.json` `[REPO]`
Name `SOC-Generic-Pipeline`, start node `Routeur`, 2 triggers (webhooks): `Wazuh_Webhook`, `Dashboard_Decision_Webhook`. 21 nodes:

| Node | Type | What it does |
|---|---|---|
| Routeur | HTTP POST | `http://192.168.56.12:9999/classify` |
| Get_VT_IP / Get_VT_HASH | HTTP GET | VirusTotal v3 `ip_addresses/<srcip>` or `files/<sha256_after>`; header `x-apikey` |
| Get_OTX_IP / Get_OTX_HASH | HTTP GET | OTX `indicators/IPv4/<ip>/general` or `indicators/file/<sha256>/general`; header `X-OTX-API-KEY` |
| Calc_Score | HTTP POST | `http://192.168.56.12:9999/` |
| AI_FP_Check | Python | see 5.3 |
| AI_Chain_Analysis | Python | see 5.3 |
| create_alert | Python | builds a text report + creates TheHive alert (`POST http://192.168.56.12:9000/api/alert`, Bearer key **inside the code**, type `wazuh`, source `shuffle`, tlp 2) |
| Create_Alert_copy | HTTP POST | TheHive alert for analyst_review (Bearer key in headers) |
| Discord_Notify / Discord_Notify_copy | HTTP POST | Discord webhook messages (alert created / analyst review) |
| Get_Wazuh_Token (+ `_copy`) | HTTP POST | `https://192.168.56.10:55000/security/user/authenticate?raw=true`, Basic auth |
| Block_IP | HTTP PUT | `.../active-response?agents_list=002` body `{"command":"!netsh","arguments":["srcip"],"alert":{"data":{"srcip":"$exec.all_fields.data.srcip"}}}` |
| Quarantine_File | HTTP PUT | same URL, body `{"command":"!quarantine","alert":{"syscheck":{"sha256_after":"$exec.all_fields.syscheck.sha256_after"}}}` |
| Block_IP_copy / Quarantine_File_copy | HTTP PUT | same, fed by dashboard payload (`$exec.srcip`, `$exec.sha256`) |
| Isolate_Agent | HTTP PUT | body `{"command":"!isolate","alert":{"data":{"srcip":""}}}` (see 9.5) |
| Send_To_Dashboard_Analyst / _FP | HTTP POST | `http://192.168.56.12:8080/api/alerts` |

All Wazuh active-response calls use **`agents_list=002`, hardcoded** (5 nodes: Block_IP, Quarantine_File, Block_IP_copy, Quarantine_File_copy, Isolate_Agent).
The quarantine call passes the **SHA256, not the file path**, because Windows backslashes break JSON. `[NOTES]`
A command starting with `!` makes Wazuh run that executable directly from the agent's `active-response\bin` folder (no `<command>` block needed in `ossec.conf`). `[INFERRED]` from Wazuh >= 4.2 behaviour.

### 5.5 Wazuh active responses on the Windows agent
- `!netsh` -> `netsh.exe`, the firewall-block active response that ships with the Windows Wazuh agent (the author does not have its source). It reads `srcip` from the Wazuh JSON and adds a Windows Firewall rule named `WAZUH ACTIVE RESPONSE BLOCKED IP` with `remoteip=<srcip> action=block`. `[NOTES]`
- `!quarantine` -> `quarantine.exe`, compiled from `1-windows-agent/quarantine.py`. `[REPO]` + `[NOTES]`
- `!isolate` -> `isolate.exe`, a custom host-isolation executable. **Not in the repo.** Per the author's notes it reads the Wazuh active-response JSON on stdin and, for command `add` (or `continue`), sets the Windows Firewall to block all inbound and outbound traffic, then adds allow rules `Allow-Wazuh-Out` and `Allow-Wazuh-In` so only the Wazuh manager connection survives. See 9.5.

**quarantine.py behaviour `[REPO]`:** reads the Wazuh active-response JSON line on stdin (`command` must be `add`; data in `parameters.alert.syscheck`); tries `syscheck.path` first; if the path is missing it searches `SCAN_DIRS` (hardcoded to one user's Downloads folder) for a file whose SHA256 equals `sha256_after`; moves the file to `C:\Quarantine\` (adds `.1`, `.2`... on name clash); logs to `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log`. The older notes say `C:\quarantine.log`; **the code's log path is the truth**. Edit `SCAN_DIRS` for a different Windows user.
Installed as `C:\Program Files (x86)\ossec-agent\active-response\bin\quarantine.exe`. `[NOTES]`

### 5.6 Dashboard: `4-score-api-and-dashboard/dashboard/` `[REPO]`
- Flask, port **8080**, SQLite file `alerts.db` created next to `app.py` at startup (`init_db()`), `requirements.txt`: `flask>=2.3.0`, `python-dotenv>=1.0.0`, `requests>=2.31.0`. Dark SOC UI; fonts loaded from Google Fonts (needs internet or falls back).
- **Env vars** (file `.env` next to `app.py`, see `dashboard/.env.example`): `DASHBOARD_SECRET_KEY`, `SHUFFLE_APPROVAL_WEBHOOK` (URL of the `Dashboard_Decision_Webhook` trigger), `ANALYST_USERNAME` (default `analyst`), `ANALYST_PASSWORD` (default `change_me`; **change it**).
- **Routes:** `GET /health`; `POST /api/alerts` (called by Shuffle, **no login**); `GET /api/alerts`, `GET /api/alerts/<id>`, `POST /api/alerts/<id>/decision` (login required); `GET /` list; `GET /alert/<id>` detail; `/login`, `/logout`.
- **Decisions** (`POST /api/alerts/<id>/decision`, body `{"decision","comment"}`): `approve_block_ip`, `approve_quarantine`, `isolate_agent` (-> status approved and webhook to Shuffle), `reject` (rejected), `mark_investigating` (investigating). Webhook is called with `verify=False`, 5 s timeout, failure only prints a warning.
- **Incident grouping:** `analyst_review` alerts from the same agent within 5 minutes (while pending/investigating) share an `incident_id` (`INC-<thehive id>`); `isolate_agent`, `reject` and `mark_investigating` apply to the whole incident.
- **Table `alerts`:** id, incident_id, source_ref, thehive_alert_id, playbook, agent_id, agent_name, rule_id, rule_description, srcip, sha256, score, severity, ai_decision, ai_confidence, ai_reason, ai_summary (JSON string for analyst_review, parsed for the `events_detail` timeline), ai_threat_level, recommended_action, status (default pending), analyst_decision, analyst_comment, created_at, decided_at.
- The detail page links to TheHive at `http://192.168.56.12:9000/alerts/...` (hardcoded IP).
- Run from its folder: `nohup python3 app.py &` `[NOTES]` (the author used nohup; no service file).

### 5.7 TheHive / Cortex: `thehive-cortex/docker-compose.yml` `[REPO]`
Elasticsearch 7.17.9 (single node, security disabled, 1 GB heap), `strangebee/thehive:5.2` (port 9000), `thehiveproject/cortex:3.1.7` (port 9001, mounts the docker socket). TheHive mounts `./config/thehive/application.conf` (**not in repo**, section 9.7) and `./data/...`. Lab path on VM5: `~/soc-lab/`.
Alerts are created as type `wazuh`, source `shuffle`, tlp 2, severity 1-4. A TheHive **API key** is required (section 7).

---

## 6. JSON contracts (useful for testing with curl)

Dashboard intake (`POST http://192.168.56.12:8080/api/alerts`), minimal test:
```json
{"sourceRef":"test-1","playbook":"block_ip","agent_id":"002","agent_name":"agent-name","rule_id":"5712",
 "rule_description":"test alert","srcip":"192.168.56.50","score":"80","severity":"critical",
 "ai_decision":"block_auto_action","ai_confidence":60,"ai_reason":"test","status":"pending"}
```
Dashboard -> Shuffle approval webhook:
```json
{"dashboard_alert_id":12,"decision":"approve_block_ip","agent_id":"002","srcip":"192.168.56.50","sha256":"","playbook":"block_ip","comment":"Approved by analyst"}
```
Score API checks:
```bash
curl -s http://192.168.56.12:9999/health
curl -s -X POST http://192.168.56.12:9999/classify -d '{"rule_id":"5712"}'    # -> playbook block_ip
curl -s -X POST http://192.168.56.12:9999/ -d '{"level":12,"firedtimes":25,"tactic":"Credential Access","playbook":"block_ip","vt_malicious_ip":8,"otx_pulses_ip":4,"srcip":"1.2.3.4"}'
```

---

## 7. Secrets and placeholders inventory

The repo never holds real values. Where each placeholder lives and what real value it needs:

| Placeholder in repo | Where it appears | Real value |
|---|---|---|
| `<GROQ_API_KEY>` | `ai_fp_check.py`, `ai_chain_analysis.py`, and inside the Python code of nodes `AI_FP_Check`, `AI_Chain_Analysis` in the JSON | Groq API key (console.groq.com) |
| `<VIRUSTOTAL_API_KEY>` | header `x-apikey` of `Get_VT_IP`, `Get_VT_HASH` | VirusTotal API key |
| `<OTX_API_KEY>` | header `X-OTX-API-KEY` of `Get_OTX_IP`, `Get_OTX_HASH` | OTX AlienVault key |
| `<THEHIVE_API_KEY>` | header `Authorization: Bearer ...` of `Create_Alert_copy` **and inside the code of node `create_alert`** | TheHive API key of an analyst/service user |
| `<WAZUH_API_BASE64_CREDENTIALS>` | header `Authorization: Basic ...` of `Get_Wazuh_Token`, `Get_Wazuh_Token_copy` | `echo -n 'APIUSER:APIPASSWORD' \| base64` (Wazuh API user, default `wazuh-wui`) |
| `https://discord.com/api/webhooks/<ID>/<TOKEN>` | `Discord_Notify`, `Discord_Notify_copy` | Discord channel webhook URL |
| `webhook_<WEBHOOK_ID>` | the two trigger URLs in the JSON | **Regenerated automatically when the workflow is imported**; copy the new URLs |
| `DASHBOARD_SECRET_KEY`, `ANALYST_PASSWORD`, `SHUFFLE_APPROVAL_WEBHOOK` | `dashboard/.env` | choose strong values; webhook = new `Dashboard_Decision_Webhook` URL |

After importing the workflow, the **Wazuh_Webhook URL must be put into the Wazuh manager `<integration>`** (9.1), and the **Dashboard_Decision_Webhook URL into the dashboard `.env`**.

---

## 8. Redeploy runbook (order matters)

Use this as the skeleton of the conversation. Verify each stage before the next.

**Stage 0: Network.** 3+ VMs and the Windows host on one host-only network `192.168.56.0/24` with the fixed IPs of section 3 (or change the IPs everywhere: they are hardcoded in the workflow JSON, `ai_chain_analysis.py`, `dashboard` templates; use `grep -rn "192.168.56" .`). Give VM4/VM5 internet access for Groq/VT/OTX/Discord (second NAT adapter).

**Stage 1: VM3, Wazuh manager 4.14.4** (install per official Wazuh docs, not part of this repo).
1. Add custom rules (9.2) and the Shuffle integration (9.1); restart `wazuh-manager`.
2. Copy `events-api.py` to `/home/ubuntu22/`, create the service (9.6), start it.
3. Verify: `curl http://192.168.56.10:8888/health` -> `{"status":"ok","service":"events-api"}`.
4. Verify the API answers: `curl -k https://192.168.56.10:55000/` (returns an auth error; that is expected).

**Stage 2: VM5, TheHive/Cortex + Score API + Dashboard.**
1. Docker + docker compose; place `docker-compose.yml` in `~/soc-lab/`, recreate `config/thehive/application.conf` (9.7), `docker compose up -d`. Check `http://192.168.56.12:9000`. Log in (see TheHive docs for the first-boot admin account), create an organisation + a user, **generate that user's API key** (this is `THEHIVE_API_KEY`).
2. `mkdir ~/score-api && cp score.py` there; start: `nohup python3 ~/score-api/score.py &`. Verify `curl http://192.168.56.12:9999/health`.
3. Dashboard: `mkdir ~/soc-dashboard`, copy `app.py requirements.txt templates static`; `python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt`; `cp .env.example .env` and fill it (the webhook comes in Stage 3); `nohup python3 app.py &`. Verify `curl http://192.168.56.12:8080/health` -> `{"service":"soc-dashboard","status":"ok"}`, then open `/login`.

**Stage 3: VM4, Shuffle** (install per Shuffle docs; the author used Docker Swarm, deployment files not in repo, 9.8).
1. Open `http://192.168.56.11:3001`, create the account.
2. Workflows -> Import -> `SOC-Generic-Pipeline.json`. Icons are stripped (default icons appear; harmless).
3. Replace every placeholder (section 7) in the listed nodes. Re-check that **Shuffle Python nodes** contain the Groq key and `create_alert` the TheHive key.
4. Copy the two **new webhook URLs** (`Wazuh_Webhook`, `Dashboard_Decision_Webhook`). Put the second into dashboard `.env` and restart the dashboard.
5. Start the workflow (the triggers must be **started**, a frequent miss).

**Stage 4: Windows host, Wazuh agent 4.14.4.**
1. Install the agent pointing to manager `192.168.56.10`. On the manager, `sudo /var/ossec/bin/agent_control -l` must show it **Active with ID `002`**. If the ID differs, change `agents_list=002` in the 5 nodes.
2. Add FIM + event config (9.3).
3. Build and install `quarantine.exe` (9.4), and the isolate executable if you want that decision (9.5). Create `C:\Quarantine\`.
4. Restart the agent: `Restart-Service WazuhSvc`.

**Stage 5: Wire and test.** Wazuh `<integration>` hook_url = `Wazuh_Webhook` URL (restart manager). Then run the tests (section 10). In Shuffle, watch the execution list; each node shows its input/output.

---

## 9. Files NOT in the repo: how to recreate them

Everything below is a **reconstruction guide**. Say so to the user. Ask for the author's original whenever possible.

### 9.1 Wazuh manager: Shuffle integration block (`ossec-custom-blocks.conf`, goes into `/var/ossec/etc/ossec.conf`)
`[INFERRED]` Wazuh ships a built-in `shuffle` integration. Template:
```xml
<integration>
  <name>shuffle</name>
  <hook_url>http://192.168.56.11:3001/api/v1/hooks/webhook_REPLACE_WITH_YOUR_ID</hook_url>
  <level>5</level>            <!-- [UNKNOWN] original level/rule filter; alternatively <rule_id>list</rule_id> -->
  <alert_format>json</alert_format>
</integration>
```
Ask the user for their original filter. Level 5 is a reasonable default (the Events API also uses min level 5). Restart: `sudo systemctl restart wazuh-manager`. Check `/var/ossec/logs/integrations.log`.

### 9.2 Custom rule(s) (`local_rules.xml`, `/var/ossec/etc/rules/local_rules.xml`)
`score.py` lists rule **`100203`** in the brute-force group. IDs 100000+ are user-defined, so the author wrote it. `[INFERRED]` Its content is `[UNKNOWN]`; the author's notes describe SSH brute force triggering IP blocking. Template to adapt (frequency rule on a base authentication-failure rule; adjust the `if_matched_sid` to what the user's log source really produces):
```xml
<group name="local,bruteforce,">
  <rule id="100203" level="10" frequency="5" timeframe="120">
    <if_matched_sid>5710</if_matched_sid>   <!-- or 5760 etc.; confirm with real alerts -->
    <same_source_ip />
    <description>Brute force: multiple authentication failures from same source IP</description>
    <mitre><id>T1110</id></mitre>
  </rule>
</group>
```
The rule must expose `data.srcip` in the alert, because the workflow blocks `$exec.all_fields.data.srcip`. Test with `sudo /var/ossec/bin/wazuh-logtest`. Also: how the author generated the demo brute-force (from which VM, against which service) is `[UNKNOWN]`: ask.

### 9.3 Windows agent config (`C:\Program Files (x86)\ossec-agent\ossec.conf`)
Needed for the file-quarantine playbook: real-time FIM with hashes on the monitored folder, so a dropped file raises a syscheck alert carrying `sha256_after`:
```xml
<syscheck>
  <directories realtime="yes" check_all="yes" report_changes="yes">C:\Users\YOURUSER\Downloads</directories>
</syscheck>
```
Rules 550/553/554 are the FIM changed/deleted/added alerts; the EICAR test drop raises **554** (file added). `[INFERRED]` Default Windows channels (Application, Security, System) are normally configured by the installer. Rules in the 92xxx range come from Wazuh's **Sysmon** rules, so if the user wants those detections they need Sysmon installed with the `Microsoft-Windows-Sysmon/Operational` channel collected; the original Sysmon config is `[UNKNOWN]`. Account/group rules (60109-60112, 60154, 60160...) need Windows **audit policy** for account management and group management (`auditpol /get /category:*` to check). The rule *descriptions* in the repo comments are the author's notes and may not match the official Wazuh descriptions: verify against the ruleset.

### 9.4 Building `quarantine.exe`
`[INFERRED]` command (original not preserved):
```powershell
pip install pyinstaller
pyinstaller --onefile quarantine.py
Copy-Item dist\quarantine.exe "C:\Program Files (x86)\ossec-agent\active-response\bin\quarantine.exe"
New-Item -ItemType Directory -Force C:\Quarantine
Restart-Service WazuhSvc
```
Test without Shuffle (run PowerShell **as Administrator**; simulates Wazuh's stdin JSON; replace the hash with the SHA256 of a file in Downloads, get it with `Get-FileHash <file>`):
```powershell
'{"version":1,"command":"add","parameters":{"alert":{"syscheck":{"sha256_after":"<SHA256>"}}}}' | & "C:\Program Files (x86)\ossec-agent\active-response\bin\quarantine.exe"
Get-Content "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -Tail 10
```

### 9.5 The `!isolate` active response (host isolation)
Called only by the dashboard decision `isolate_agent` through node `Isolate_Agent`. The author's notes show an `isolate.py` (a C# `isolate.exe` is also mentioned, compiled with `csc.exe`); the final executable lives in `active-response\bin\isolate.exe`. The source is **not in the repo**, and the notes only show the start of the code, so the exact firewall parameters and the restore step are `[UNKNOWN]`. What is known: it reads the Wazuh JSON on stdin, blocks all inbound and outbound traffic, and keeps only the Wazuh manager connection through rules named `Allow-Wazuh-Out` and `Allow-Wazuh-In`.

**Reconstruction** (not the original; adapt and test on a lab machine you can reach from the console, because a mistake cuts the network):
```python
import sys, json, subprocess
MANAGER = "192.168.56.10"

def run(cmd): subprocess.run(cmd, shell=True)

for line in sys.stdin:
    command = json.loads(line.strip()).get("command")
    if command in ("add", "continue"):          # isolate
        run("netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound")
        run(f'netsh advfirewall firewall add rule name="Allow-Wazuh-Out" dir=out action=allow remoteip={MANAGER} protocol=TCP')
        run(f'netsh advfirewall firewall add rule name="Allow-Wazuh-In" dir=in action=allow remoteip={MANAGER} protocol=TCP')
    elif command == "delete":                   # restore (sent when an active-response timeout is configured)
        run("netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound")
        run('netsh advfirewall firewall delete rule name="Allow-Wazuh-Out"')
        run('netsh advfirewall firewall delete rule name="Allow-Wazuh-In"')
    break
```
Build and install it like `quarantine.exe` (9.4): `pyinstaller --onefile isolate.py`, copy `isolate.exe` to `active-response\bin`. Warn the user how to undo it by hand (run the three restore commands from an Administrator prompt on the console). Everything else works without it.

### 9.6 systemd units (reconstructed)
Events API (on VM3). It needs to read `alerts.json`, which is not world-readable, hence root:
```ini
# /etc/systemd/system/events-api.service
[Unit]
Description=Wazuh Events API
After=network.target wazuh-manager.service

[Service]
ExecStart=/usr/bin/python3 /home/ubuntu22/events-api.py
Restart=always
User=root
StandardOutput=append:/var/log/events-api.log
StandardError=append:/var/log/events-api.log

[Install]
WantedBy=multi-user.target
```
`sudo systemctl daemon-reload && sudo systemctl enable --now events-api`. The author ran **Score API and Dashboard with `nohup`** (no unit). Units of the same shape (`WorkingDirectory=/home/ubuntu22/soc-dashboard`, `ExecStart=/home/ubuntu22/soc-dashboard/venv/bin/python app.py`) are a fine upgrade; offer, do not impose.

### 9.7 TheHive `config/thehive/application.conf`
Not in repo (it holds a secret key and DB settings). `[UNKNOWN]` content. Rebuild from the StrangeBee TheHive 5.2 Docker documentation for a single node with Elasticsearch at `http://elasticsearch:9200`; generate a fresh `play.http.secret.key`. Without it the compose file cannot start TheHive.

### 9.8 Shuffle deployment
Shuffle itself is open source. The author deployed it on **Docker Swarm** `[NOTES]` (justified in the report); the swarm/compose files are not in the repo. Use Shuffle's official docker-compose install; Swarm is not required for this project to function. Default ports 3001 (UI) / 5001 (backend) match the author's.

### 9.9 Other absent files
`tests/` scripts (section 10 gives the commands), `docs/` screenshots and the architecture diagram, the LaTeX report. If asked for an architecture diagram, draw one from sections 3-4.

---

## 10. Test scenarios (run on the Windows host, in the user's own lab)

| Test | Command | Expected path |
|---|---|---|
| **isolate_agent / quarantine** | `Set-Content -Path "$env:USERPROFILE\Downloads\eicar.txt" -Value 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'` (harmless EICAR test string; antivirus may react) | FIM rule 554 -> Routeur -> VT/OTX hash -> Calc_Score -> AI_FP_Check -> TheHive + Discord -> Quarantine_File (file moves to `C:\Quarantine`), or dashboard if AI confidence is low |
| **analyst_review** | `net user backdoor Password123! /add` then `net localgroup administrators backdoor /add` (admin PowerShell; cleanup: `net user backdoor /delete`) | Account/group rules -> Routeur -> AI_Chain_Analysis -> TheHive -> Discord -> dashboard pending alert; **no automatic action** |
| **block_ip** | brute force the monitored service so rule 5712/5763/5710/5716/100203/40111 fires `[UNKNOWN]` how the author did it | Routeur -> VT/OTX IP -> Calc_Score -> AI_FP_Check -> TheHive -> Discord -> Block_IP via `netsh`, or dashboard |

Since external threat-intel for lab IPs (e.g. `192.168.56.x`) is always clean, an automatic block usually depends on the AI/score; to force the dashboard path use a low-confidence case, to force the approval path use the manual `curl` dashboard test in section 6.

---

## 11. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Nothing reaches Shuffle | Integration block missing/wrong hook_url, workflow not started, wrong webhook ID, manager not restarted. Check `/var/ossec/logs/integrations.log` |
| Webhook works but nothing after Routeur | Score API down (`curl :9999/health`), or rule not in any list -> `log_only` (by design stops) |
| `$something` appears literally in a request body | Node label renamed; Shuffle variables follow node labels in lower case |
| `Create_Alert` / TheHive 401/403 | TheHive key missing/expired or user lacks alert-create rights; remember the key is in **two** places (`Create_Alert_copy` headers and `create_alert` code) |
| Wazuh API 401 | Bad Basic credentials; token has a short lifetime (node fetches a new one each run) |
| Active response 200 but nothing happens | Agent ID is not `002`; agent offline; `quarantine.exe` not in `active-response\bin`; check `active-responses.log` and `ossec.log` on the agent |
| File not quarantined | Hash not found: file not in `SCAN_DIRS`, already moved, or SHA256 not in the alert (FIM `check_all`/realtime missing) |
| AI nodes return fallback "AI indisponible" | Groq key missing/rate-limited, or no internet from VM4. The system then deliberately **blocks automation** and sends to the dashboard |
| Dashboard approvals do nothing | `SHUFFLE_APPROVAL_WEBHOOK` empty/wrong in `.env`; dashboard not restarted; `Dashboard_Decision_Webhook` not started; the dashboard only prints a warning on failure (check `nohup.out`) |
| Dashboard login fails | `ANALYST_USERNAME/PASSWORD` in `.env`; defaults are `analyst` / `change_me` |
| Events API returns empty | Wrong agent id, `alerts.json` unreadable by the service user, or no alert >= level 5 matching "suspicious" |
| TheHive will not start | Missing `application.conf`, Elasticsearch not healthy yet (`curl :9200`), too little RAM (the stack needs several GB) |
| Wazuh API/TLS errors in Shuffle | Self-signed certificate; the HTTP app must accept it (the author's setup did) |

---

## 12. Known issues and quirks (be upfront about them)

1. **Rule `60107` is missing from `suspicious_rules` in `score.py`**, although the author's notes list it for analyst review and the Events API includes it. Such alerts fall into `log_only`. Fix: add `'60107'` to the list.
2. **Rule `'92021'` is swallowed by a comment** on the `'92213'` line in `score.py` (a comment runs over it), so it is not in the list. Fix: put it on its own line.
3. **Events API vs router mismatch:** `60125`, `60145`, `92057` are "interesting" in the Events API but absent from the router, so they classify as `log_only`.
4. **Confidence threshold off-by-one:** `ai_fp_check.py` allows auto action when `action_confidence > 74` (so 75 passes) while the Shuffle edge requires `> 75` for automatic action and `< 76` for the dashboard. At exactly 75 the result is "dashboard", not auto. Harmless but worth knowing; the author's documented thresholds are "`> 75` auto, `< 76` dashboard".
5. **TheHive alert and Discord notification are always sent** after `AI_FP_Check`, even when automation is blocked; only the response (block/quarantine) is gated.
6. **Agent ID `002` and the Windows username in `SCAN_DIRS` are hardcoded** (5 Shuffle nodes; `SCAN_DIRS`). The dashboard decision payload carries `agent_id`, but the nodes ignore it.
7. `Isolate_Agent` sends an empty `srcip` and depends on `isolate.exe`, which is not in the repo (reconstruction in 9.5).
8. `POST /api/alerts` on the dashboard has **no authentication** (lab convenience); do not expose port 8080 beyond the host-only network.
9. The Wazuh API calls and the dashboard webhook disable TLS verification (self-signed lab certificates).
10. "Block IP for 6 hours / 1 hour" in the recommended-action text is **not implemented**; the block is permanent until removed from the Windows firewall.
11. Older notes call the file-quarantine script `quarantine.ps1` and mention a log `C:\quarantine.log`; the final code is `quarantine.py` logging to `active-responses.log`.
12. If any Groq, VirusTotal, OTX or TheHive key was ever exposed (exports, chat, screenshots), **rotate** it.

---

## 13. Questions to ask the human when needed

- Are you rebuilding for a demo, to learn, or for an existing setup? (decides how much to reconstruct)
- Your Wazuh agent ID and name? Your Windows username? (hardcoded values)
- The original `<integration>` filter, rule `100203`, Windows syscheck/Sysmon config, and `isolate` binary: do you still have them?
- How is the brute-force simulated in your lab, and which service logs it?
- What are the roles of the other lab VMs?
- Do you want systemd services instead of `nohup`?

---

## 14. Glossary

**SIEM** Wazuh: collects logs, raises alerts. **SOAR** Shuffle: automates workflows. **Active Response** Wazuh feature that runs a script on an agent (block, quarantine). **FIM / syscheck** file integrity monitoring. **TLP** traffic light protocol label on TheHive alerts. **MITRE ATT&CK** attack technique catalogue used for tactics in the score. **FP** false positive.
