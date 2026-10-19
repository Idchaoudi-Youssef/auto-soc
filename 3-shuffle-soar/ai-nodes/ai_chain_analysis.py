import requests
import json

# ============= CONFIG =============
EVENTS_API = "http://192.168.56.10:8888"
GROQ_API = "https://api.groq.com/openai/v1/chat/completions"
GROQ_API_KEY = "<GROQ_API_KEY>"
GROQ_MODEL = "llama-3.3-70b-versatile"

# ============= INPUT FROM SHUFFLE =============
agent_id = "$exec.all_fields.agent.id"
agent_name = "$exec.all_fields.agent.name"
current_rule_id = "$exec.all_fields.rule.id"
current_rule_desc = "$exec.all_fields.rule.description"
current_rule_level = "$exec.all_fields.rule.level"
playbook = "$routeur.body.playbook"

THREAT_TO_SEVERITY = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

result = {
    "ai_analysis": {},
    "thehive_severity": 2,
    "timeline": [],
    "error": None,
    "status": "ok"
}

# ============= 1. GET RECENT EVENTS =============
try:
    r = requests.get(
        f"{EVENTS_API}/agent/{agent_id}/recent",
        params={"limit": 10, "suspicious_only": "true"},
        timeout=10
    )
    r.raise_for_status()
    events_data = r.json()
    timeline = events_data.get("alerts", [])
    result["timeline"] = timeline
except Exception as e:
    result["error"] = f"Failed to fetch timeline: {str(e)}"
    timeline = []

# ============= 2. BUILD PROMPT =============
timeline_text = ""
for i, ev in enumerate(timeline[:10]):
    eid = ev.get("eventID", "")
    rid = ev.get("rule_id", "")
    desc = ev.get("description", "")
    tact = ", ".join(ev.get("mitre_tactic", [])) or "N/A"
    tech = ", ".join(ev.get("mitre_technique", [])) or "N/A"
    edata = ev.get("eventdata", {})
    subject = edata.get("subjectUserName", "")
    target = edata.get("targetUserName", "")
    member_sid = edata.get("memberSid", "")
    ts = ev.get("timestamp", "")[:19] if ev.get("timestamp") else ""
    user_str = ""
    if subject:
        user_str += f" | actor: {subject}"
    if target:
        user_str += f" | target_group: {target}"
    if member_sid:
        user_str += f" | member_sid: {member_sid}"
    timeline_text += f"  {i+1}. [{ts}] Rule {rid} (EID {eid}): {desc} | MITRE tactic: {tact} | technique: {tech}{user_str}\n"

if not timeline_text:
    timeline_text = "  (No recent suspicious events found)\n"

prompt = f"""Tu es un analyste SOC senior. Analyse cette CHAINE d'evenements sur l'agent {agent_name}.

EVENEMENT DECLENCHEUR:
- Regle: {current_rule_id} - {current_rule_desc}
- Niveau Wazuh: {current_rule_level}

TIMELINE DES 10 DERNIERS EVENEMENTS SUSPECTS (du plus recent au plus ancien):
{timeline_text}

IMPORTANT:
1. Tu DOIS inclure le champ "events_detail" avec UNE ENTREE PAR EVENEMENT. OBLIGATOIRE.
2. Pour "mitre_tactics_observed", toujours inclure le code T avec le nom (ex: "T1136 - Create Account", "T1484 - Domain Policy Modification"). Ne jamais mettre juste le nom sans le code T.
3. Pour "mitre_technique" dans events_detail, toujours inclure le code T (ex: "T1484 - Domain Policy Modification").

Reponds UNIQUEMENT en JSON valide (pas de markdown):
{{
  "chain_detected": true,
  "attack_pattern": "Privilege Escalation",
  "events_correlated": 10,
  "summary": "Resume en 2-3 phrases en francais",
  "threat_level": "CRITICAL",
  "confidence_percent": 95,
  "is_likely_false_positive": false,
  "recommended_actions": ["Action 1", "Action 2", "Action 3"],
  "mitre_tactics_observed": ["T1136 - Create Account", "T1484 - Domain Policy Modification"],
  "analyst_priority": "P1",
  "events_detail": [
    {{
      "timestamp": "2026-06-28T12:10:12",
      "rule_id": "60154",
      "description": "Administrators Group Changed",
      "mitre_tactic": "Privilege Escalation",
      "mitre_technique": "T1484 - Domain Policy Modification",
      "user": "void (actor) ajoute dans Administrators (target)",
      "significance": "Un compte a ete ajoute au groupe Administrateurs — escalade de privileges critique"
    }},
    {{
      "timestamp": "2026-06-28T12:10:11",
      "rule_id": "60109",
      "description": "User account enabled or created",
      "mitre_tactic": "Persistence",
      "mitre_technique": "T1136 - Create Account",
      "user": "void (actor) a cree le compte backdoor",
      "significance": "Creation d un nouveau compte utilisateur suspect"
    }}
  ]
}}

Remplis events_detail avec TOUS les evenements de la timeline fournie ci-dessus, un objet par evenement."""

# ============= 3. CALL GROQ =============
try:
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    body = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": "Tu es un analyste SOC senior. Tu reponds UNIQUEMENT en JSON valide. Tu dois TOUJOURS inclure le champ events_detail avec une entree pour chaque evenement de la timeline. Pour mitre_tactics_observed et mitre_technique, toujours inclure le code T (ex: T1136, T1484) suivi du nom."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3,
        "response_format": {"type": "json_object"}
    }

    resp = requests.post(GROQ_API, headers=headers, json=body, timeout=30)

    if resp.status_code == 200:
        groq_response = resp.json()
        ai_text = groq_response["choices"][0]["message"]["content"]
        try:
            result["ai_analysis"] = json.loads(ai_text)
        except json.JSONDecodeError:
            result["ai_analysis"] = {"raw": ai_text, "parse_error": True}
            result["error"] = "AI returned invalid JSON"
    else:
        result["error"] = f"Groq API error {resp.status_code}"
        result["ai_analysis"] = {
            "chain_detected": len(timeline) >= 3,
            "attack_pattern": "AI unavailable - basic detection",
            "events_correlated": len(timeline),
            "summary": f"AI service indisponible. {len(timeline)} evenements suspects detectes.",
            "threat_level": "MEDIUM",
            "confidence_percent": 50,
            "is_likely_false_positive": False,
            "recommended_actions": ["Investiguer manuellement"],
            "mitre_tactics_observed": [],
            "analyst_priority": "P3",
            "events_detail": []
        }

except Exception as e:
    result["error"] = f"Groq call failed: {str(e)}"
    result["ai_analysis"] = {
        "chain_detected": False,
        "attack_pattern": "Error",
        "summary": f"Erreur d'analyse: {str(e)}",
        "threat_level": "UNKNOWN",
        "confidence_percent": 0,
        "is_likely_false_positive": False,
        "recommended_actions": ["Investiguer manuellement"],
        "mitre_tactics_observed": [],
        "analyst_priority": "P3",
        "events_detail": []
    }

# ============= 4. COMPUTE THEHIVE SEVERITY =============
ai_threat = result["ai_analysis"].get("threat_level", "MEDIUM")
result["thehive_severity"] = THREAT_TO_SEVERITY.get(ai_threat, 2)

# ============= 5. RETURN =============
print(json.dumps(result, default=str))