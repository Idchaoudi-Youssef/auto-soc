# How to deploy

Alert flow: **Wazuh → Shuffle → Score API → VirusTotal / OTX → AI (Groq) → TheHive + Discord → automatic response, or the analyst dashboard for a human decision.**

This repo contains only our own code and workflow. Wazuh, Shuffle, TheHive and Cortex are installed from their official docs. Several configuration items are **not in the repo** and you must create them (marked **MISSING** below).

## Machines (host-only network 192.168.56.0/24, fixed IPs)

| Machine | Runs | IP |
|---|---|---|
| Wazuh server | Wazuh manager 4.14.4 + Events API (:8888) | 192.168.56.10 |
| Shuffle server | Shuffle (:3001) | 192.168.56.11 |
| SOC server | TheHive (:9000), Cortex (:9001), Score API (:9999), Dashboard (:8080) | 192.168.56.12 |
| Windows endpoint | Wazuh agent + `quarantine.exe` | 192.168.56.1 |

The IPs are hardcoded in the workflow JSON and scripts. If you use others, run `grep -rn "192.168.56" .` and change them. The SOC server and Shuffle server need internet access (Groq, VirusTotal, OTX, Discord).

## You need accounts and keys

Groq, VirusTotal, OTX, a Discord channel webhook, and a TheHive API key (created in step 2). Never commit them. The placeholders in the repo (`<GROQ_API_KEY>` etc.) are listed in `.env.example`.

---

## Files you must configure

Nothing runs unchanged. Edit these before or while deploying:

| File | What to change |
|---|---|
| Shuffle workflow (after import) | All keys (table in step 3), the `agents_list=002` agent ID in 5 nodes, IPs if yours differ, Discord webhook, both webhook URLs |
| `3-shuffle-soar/ai-nodes/*.py` | Reference copies of the AI nodes. The code that runs is inside the Shuffle nodes, so put the Groq key there. `ai_chain_analysis.py` also holds the Events API address |
| `1-windows-agent/quarantine.py` | `SCAN_DIRS` (the folder Wazuh monitors); `QUARANTINE_DIR` and `LOG_FILE` if your paths differ |
| `2-wazuh-manager/events-api/events-api.py` | Only `ALERTS_FILE` / `PORT` if your Wazuh paths or ports differ |
| `4-score-api-and-dashboard/score-api/score.py` | No configuration needed. Edit the rule lists to change which Wazuh rules trigger which playbook |
| `4-score-api-and-dashboard/dashboard/.env` | `DASHBOARD_SECRET_KEY` and `ANALYST_PASSWORD` are **mandatory** (the app refuses to start while either still holds the placeholder). Also `ANALYST_USERNAME`, `SHUFFLE_APPROVAL_WEBHOOK` and the optional `INGEST_TOKEN` |
| `4-score-api-and-dashboard/dashboard/templates/alert_detail.html` | The TheHive link contains the server IP |
| `4-score-api-and-dashboard/thehive-cortex/docker-compose.yml` | Ports and memory settings for your machine |

---

## 1. Wazuh server

1. Install Wazuh manager 4.14.4 (official docs).
2. **MISSING: Shuffle integration.** Add to `/var/ossec/etc/ossec.conf` (you get the hook URL in step 3):
   ```xml
   <integration>
     <name>shuffle</name>
     <hook_url>http://192.168.56.11:3001/api/v1/hooks/webhook_YOUR_ID</hook_url>
     <level>5</level>
     <alert_format>json</alert_format>
   </integration>
   ```
3. **MISSING: custom brute-force rule `100203`.** The Score API routes it to the block-IP playbook. Create it in `/var/ossec/etc/rules/local_rules.xml` for your log source. It must produce `data.srcip`. Example:
   ```xml
   <group name="local,bruteforce,">
     <rule id="100203" level="10" frequency="5" timeframe="120">
       <if_matched_sid>5710</if_matched_sid>
       <same_source_ip />
       <description>Brute force: repeated authentication failures from one IP</description>
     </rule>
   </group>
   ```
   Test with `/var/ossec/bin/wazuh-logtest`. You can also skip it: rules 5712, 5763, 5710 and 5716 already trigger the same playbook.
4. Restart: `sudo systemctl restart wazuh-manager`.
5. **MISSING: Events API service.** Copy `2-wazuh-manager/events-api/events-api.py` to `/home/ubuntu22/` and create `/etc/systemd/system/events-api.service` (root is needed to read `alerts.json`):
   ```ini
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
   `sudo systemctl daemon-reload && sudo systemctl enable --now events-api`
   Check: `curl http://192.168.56.10:8888/health`

## 2. SOC server

1. **MISSING: TheHive config.** Install Docker, put `4-score-api-and-dashboard/thehive-cortex/docker-compose.yml` in a folder, and create `config/thehive/application.conf` next to it (single node, Elasticsearch at `http://elasticsearch:9200`, your own secret key; see the TheHive 5 Docker docs). Then `docker compose up -d`.
2. Open `http://192.168.56.12:9000`, create an organisation and a user, and **generate that user's API key**. You will paste it into Shuffle.
3. Score API (Python standard library only, no install):
   ```bash
   mkdir ~/score-api && cp score.py ~/score-api/
   nohup python3 ~/score-api/score.py &
   curl http://192.168.56.12:9999/health
   ```
4. Dashboard:
   ```bash
   mkdir ~/soc-dashboard && cp -r app.py requirements.txt templates static .env.example ~/soc-dashboard/
   cd ~/soc-dashboard && python3 -m venv venv && . venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env     # set DASHBOARD_SECRET_KEY and ANALYST_PASSWORD; SHUFFLE_APPROVAL_WEBHOOK comes from step 3
   # the dashboard refuses to start while either secret still holds the placeholder.
   # generate a strong value with:
   #   python3 -c "import secrets; print(secrets.token_urlsafe(32))"
   nohup python3 app.py &
   curl http://192.168.56.12:8080/health
   ```
   Keep port 8080 inside the lab network. `POST /api/alerts` is open while `INGEST_TOKEN` is empty in `.env`. To require a shared secret, set `INGEST_TOKEN=<random>` and add the header `X-Ingest-Token: <value>` to the Shuffle node that posts to `/api/alerts`.

## 3. Shuffle server

1. Install Shuffle (official docs) and open `http://192.168.56.11:3001`.
2. Workflows → Import → `3-shuffle-soar/workflows/SOC-Generic-Pipeline.json`.
3. **MISSING: all secrets.** Replace each placeholder:

   | Placeholder | Where |
   |---|---|
   | `<GROQ_API_KEY>` | code of nodes `AI_FP_Check`, `AI_Chain_Analysis` |
   | `<VIRUSTOTAL_API_KEY>` | header of `Get_VT_IP`, `Get_VT_HASH` |
   | `<OTX_API_KEY>` | header of `Get_OTX_IP`, `Get_OTX_HASH` |
   | `<THEHIVE_API_KEY>` | header of `Create_Alert_copy` **and inside the code of `create_alert`** |
   | `<WAZUH_API_BASE64_CREDENTIALS>` | header of `Get_Wazuh_Token`, `Get_Wazuh_Token_copy`. Value: `echo -n 'apiuser:apipassword' \| base64` |
   | `https://discord.com/api/webhooks/<ID>/<TOKEN>` | `Discord_Notify`, `Discord_Notify_copy` |

4. Importing creates **new webhook URLs**. Copy the one from trigger `Wazuh_Webhook` into the Wazuh `<integration>` (step 1.2, then restart the manager). Copy the one from `Dashboard_Decision_Webhook` into the dashboard `.env` as `SHUFFLE_APPROVAL_WEBHOOK`, then restart the dashboard.
5. **Start** the workflow (both triggers).

## 4. Windows endpoint

1. Install the Wazuh agent 4.14.4 pointing to `192.168.56.10`.
2. **MISSING: agent ID.** The Shuffle response nodes use `agents_list=002`. On the Wazuh server run `sudo /var/ossec/bin/agent_control -l` and check your agent's ID. If it is not `002`, change it in the nodes `Block_IP`, `Quarantine_File`, `Block_IP_copy`, `Quarantine_File_copy`, `Isolate_Agent`.
3. **MISSING: file monitoring.** Add to the agent's `ossec.conf` (adapt the folder), so dropped files raise alerts with a SHA256:
   ```xml
   <syscheck>
     <directories realtime="yes" check_all="yes" report_changes="yes">C:\Users\YOURUSER\Downloads</directories>
   </syscheck>
   ```
4. **MISSING: `quarantine.exe`.** Edit `SCAN_DIRS` in `1-windows-agent/quarantine.py` to the same folder, then build and install it (PowerShell as Administrator):
   ```powershell
   pip install pyinstaller
   pyinstaller --onefile quarantine.py
   Copy-Item dist\quarantine.exe "C:\Program Files (x86)\ossec-agent\active-response\bin\quarantine.exe"
   New-Item -ItemType Directory -Force C:\Quarantine
   Restart-Service WazuhSvc
   ```
   The IP-blocking response (`netsh.exe`) ships with the Wazuh agent.
5. **Optional, MISSING: Sysmon and audit policy.** Some analyst-review rules need them. The 92xxx rules need Sysmon with its channel collected. The account and group rules (60109–60112, 60154, 60160) need Windows auditing for account management and security group management.
6. **Optional, MISSING: `isolate` response.** The dashboard's "isolate agent" button calls `!isolate`, an executable that is not in the repo (it cuts the machine off the network except the Wazuh connection). Without it that single button does nothing; everything else works. A script to recreate it is in section 9.5 of `everythingunee2know-giveittoai.md`; build it like `quarantine.exe` and name it `isolate.exe`.

## 5. Test

On the Windows endpoint (your own lab only):

- **Quarantine:** `Set-Content -Path "$env:USERPROFILE\Downloads\eicar.txt" -Value 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'`. The file should move to `C:\Quarantine`, or appear on the dashboard if the AI is not confident.
- **Analyst review** (admin PowerShell): `net user backdoor Password123! /add` then `net localgroup administrators backdoor /add`. A pending alert should appear on the dashboard and no automatic action runs. Clean up with `net user backdoor /delete`.
- **Block IP:** generate repeated failed logins on a service your Wazuh agent monitors, so rule 5712, 5763, 5710, 5716 or 100203 fires.
- **Dashboard without Shuffle:** `curl -X POST http://192.168.56.12:8080/api/alerts -H 'Content-Type: application/json' -d '{"playbook":"block_ip","agent_id":"002","rule_id":"5712","rule_description":"test","srcip":"192.168.56.50","status":"pending"}'`

Watch each run in Shuffle's execution view: every node shows its input and output.

## If it does not work

| Problem | Check |
|---|---|
| Nothing reaches Shuffle | `<integration>` URL, workflow started, manager restarted; `/var/ossec/logs/integrations.log` |
| Stops after the first node | Score API running; rule ID is in no list (then it is ignored on purpose) |
| TheHive alert fails | API key in **both** places (`Create_Alert_copy` and `create_alert`) |
| Response does nothing | Agent ID, `quarantine.exe` location, agent `active-responses.log` |
| Dashboard approvals do nothing | `SHUFFLE_APPROVAL_WEBHOOK` in `.env`, dashboard restarted, trigger started |
| AI node says "AI indisponible" | Groq key or internet access; the system then sends the alert to the dashboard instead of acting |
