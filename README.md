<div align="center">

# 🛡️ Auto SOC

### Automated SOC / SOAR Platform

*Detect · Enrich · Score · Respond — and hand the uncertain ones to a human.*

<br>

![Wazuh](https://img.shields.io/badge/Wazuh-4.14.4-0077C8?style=for-the-badge&logo=wazuh&logoColor=white)
![Shuffle](https://img.shields.io/badge/Shuffle-SOAR-FF8C00?style=for-the-badge)
![TheHive](https://img.shields.io/badge/TheHive-5-F5B800?style=for-the-badge)
![Groq](https://img.shields.io/badge/Groq-Llama%203.3%2070B-7B2FF7?style=for-the-badge)
<br>
![Python](https://img.shields.io/badge/Python-3-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Dashboard-000000?style=for-the-badge&logo=flask&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Status](https://img.shields.io/badge/Status-Lab%20Project-2EA44F?style=for-the-badge)

<br>

[**How it works**](#-how-it-works) ·
[**Highlights**](#-highlights) ·
[**Screenshots**](#-screenshots) ·
[**Stack**](#-stack) ·
[**Deploy**](#-deploy-it) ·
[**Use an AI**](#-using-an-ai-assistant)

</div>

<br>

---

**Wazuh** detects → **Shuffle** orchestrates → a custom **Score API** scores the alert (NIST-inspired, 0–100) using **VirusTotal** and **OTX** → an **LLM (Groq, Llama 3.3 70B)** decides whether automatic action is safe → **TheHive** and **Discord** are notified → the endpoint is protected through **Wazuh Active Response**, or a **Flask analyst dashboard** asks a human to decide.

> [!NOTE]
> Lab project built to demonstrate the concept. It is not production software.

<div align="center">

![Full architecture](docs/architecture.png)

</div>

<br>

## ⚙️ How it works

Every Wazuh alert is classified by rule ID into one of three scenarios:

| | Scenario | Typical trigger | What happens |
|:-:|---|---|---|
| 🚫 | **Block IP** | SSH / authentication brute force | Enrich the IP (VirusTotal, OTX) → score → AI false-positive check → TheHive alert → **block the IP** in the Windows firewall |
| 🦠 | **Quarantine file** | Malware / file-integrity events | Enrich the file hash → score → AI false-positive check → TheHive alert → **move the file to quarantine** |
| 🕵️ | **Analyst review** | Suspicious activity (new admin account, group changes...) | AI correlates the recent events into an attack chain → TheHive alert → **dashboard**, no automatic action |

When the AI is not confident enough, or the behaviour is only suspicious, the alert waits on the dashboard. The analyst approves a block, a quarantine or a host isolation, or rejects it as a false positive, and Shuffle executes the decision.

<div align="center">

![Pipeline flow](docs/pipeline-flow.png)

</div>

<br>

## ✨ Highlights

<table>
<tr>
<td width="50%" valign="top">

### 🧑‍💻 Human in the loop
Automation only runs when the AI is confident and the alert is not a likely false positive. If the AI is unavailable, it **fails safe** and sends the alert to the analyst.

</td>
<td width="50%" valign="top">

### 📊 Explainable scoring
Five equal criteria (Wazuh level, VirusTotal, OTX, MITRE tactic, frequency) plus a bonus, with a full evidence report attached to every TheHive alert.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🧠 AI attack-chain analysis
Correlates the last suspicious events of an endpoint and explains them in a short summary with MITRE tactics.

</td>
<td width="50%" valign="top">

### 🗂️ Incident grouping
Related analyst-review alerts are merged into one incident on the dashboard.

</td>
</tr>
</table>

> 🔗 **Everything is orchestrated in Shuffle:** all response actions go through the Wazuh Active Response API.

<br>

## 📸 Screenshots

<div align="center">

**Shuffle workflow**

![Shuffle workflow](docs/shuffle-workflow.png)

<br>

**Analyst dashboard**

![Dashboard](docs/dashboard.png)

<br>

**Incident detail with AI attack-chain analysis**

<img src="docs/alert-detail.png" alt="Alert detail" width="640">

<br><br>

**TheHive alert created by Shuffle**

![TheHive alert](docs/thehive-alert.png)

<br>

**Discord notifications**

![Discord alerts](docs/discord-alert.png)

</div>

<br>

## 🧰 Stack

| Layer | Technologies |
|---|---|
| **Detection** | Wazuh 4.14.4 |
| **Orchestration** | Shuffle (SOAR) |
| **Case management** | TheHive 5 + Cortex |
| **Custom code** | Python (Score API, Events API, active-response scripts) · Flask + SQLite (dashboard) |
| **Intelligence** | VirusTotal · OTX AlienVault · Groq (Llama 3.3 70B) |
| **Notifications & infra** | Discord · Docker |

<br>

## 🎓 Academic project

This platform is the end-of-year project (*projet de fin d'année*, 2025–2026) of the **Network Engineering and Information Security** track at **ENIAD** — École Nationale de l'Intelligence Artificielle et du Digital, Berkane (Université Mohammed Premier, Oujda, Morocco).

📄 The full academic report (80 pages, French) is included as [`rapport_academique.pdf`](rapport_academique.pdf).

<br>

## 📁 Repository

```text
auto_soc/
├── 1-windows-agent/             Windows endpoint: quarantine active-response script
├── 2-wazuh-manager/             Wazuh server: Events API
├── 3-shuffle-soar/              Shuffle workflow + the two AI nodes
├── 4-score-api-and-dashboard/   SOC server: Score API, analyst dashboard, TheHive/Cortex compose file
│   └── legacy-decision-api/     Early prototype, superseded by the Flask dashboard (kept for reference)
└── docs/                        Screenshots and diagrams
```

<br>

## 🚀 Deploy it

> **Read [`DEPLOY.md`](DEPLOY.md).** It explains the installation step by step, which files you must configure, and the parts that are not in this repository and that you must create yourself.

<br>

## 🤖 Using an AI assistant?

Give your assistant [`everythingunee2know-giveittoai.md`](everythingunee2know-giveittoai.md). It contains the complete context of the project (architecture, every component, payloads, thresholds, known issues and how to recreate the missing files), so it can guide you through the deployment and help you rebuild what the repository does not include.

<br>

---

<div align="center">

🔒 *No secrets are stored in this repository. Every key is a placeholder such as* `<GROQ_API_KEY>`*. Use your own keys and never commit them.*

</div>
