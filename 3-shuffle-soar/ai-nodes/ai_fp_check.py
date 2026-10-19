import requests
import json

# ============= CONFIG =============
GROQ_API = "https://api.groq.com/openai/v1/chat/completions"
GROQ_API_KEY = "<GROQ_API_KEY>"
GROQ_MODEL = "llama-3.3-70b-versatile"

# ============= INPUT FROM SHUFFLE =============
score = "$calc_score.body.score"
severity = "$calc_score.body.severity"
recommended_action = "$calc_score.body.recommended_action"
agent_name = "$exec.all_fields.agent.name"
agent_id = "$exec.all_fields.agent.id"
rule_id = "$exec.all_fields.rule.id"
rule_desc = "$exec.all_fields.rule.description"
rule_level = "$exec.all_fields.rule.level"
firedtimes = "$exec.all_fields.rule.firedtimes"
srcip = "$exec.all_fields.data.srcip"
playbook = "$routeur.body.playbook"
vt_detail = "$calc_score.body.details.vt.detail"
otx_detail = "$calc_score.body.details.otx.detail"
wazuh_detail = "$calc_score.body.details.wazuh.detail"
freq_detail = "$calc_score.body.details.freq.detail"

result = {
    "likely_false_positive": False,
    "fp_confidence": 0,
    "action_confidence": 50,
    "reason": "Fallback decision",
    "decision": "block_auto_action",
    "recommended_action": recommended_action,
    "status": "ok",
    "error": None
}

prompt = f"""
Tu es un analyste SOC senior dans un système SOAR automatisé.

CONTEXTE IMPORTANT SUR LE SYSTEME:
- Ce système a UNE SEULE action automatique possible: BLOQUER l'IP ou QUARANTINER le fichier.
- "allow_auto_action" = l'action de blocage/quarantaine s'exécute IMMÉDIATEMENT sans humain.
- "block_auto_action" = l'alerte est envoyée à un analyste humain pour décision manuelle.

Tu dois retourner DEUX niveaux de confiance distincts:
1. fp_confidence (0-100): à quel point tu es certain que c'est un FAUX POSITIF.
   - 0 = certainement pas un faux positif (alerte réelle)
   - 100 = certainement un faux positif (action automatique dangereuse)
   
2. action_confidence (0-100): à quel point tu es certain que l'action automatique est SÛRE à exécuter.
   - 0 = dangereux d'agir automatiquement (trop ambigu)
   - 100 = très sûr d'exécuter l'action automatiquement

CONTEXTE DE L'ALERTE:
- Playbook: {playbook}
- Action automatique prévue: {recommended_action}
- Agent: {agent_name} ({agent_id})
- Règle: {rule_id} - {rule_desc}
- Niveau Wazuh: {rule_level}
- Fois déclenchée: {firedtimes}
- IP Source: {srcip}

SCORE ENGINE (0-100):
- Score: {score}/100
- Sévérité: {severity}

ENRICHISSEMENTS THREAT INTEL:
- VirusTotal: {vt_detail}
- OTX AlienVault: {otx_detail}
- Wazuh: {wazuh_detail}
- Fréquence: {freq_detail}

RÈGLES STRICTES:
- Si fp_confidence > 60 → likely_false_positive=true ET decision="block_auto_action"
- Si action_confidence > 74 ET fp_confidence < 40 → decision="allow_auto_action"
- Ces règles sont ABSOLUES, pas de contradiction possible.

Réponds UNIQUEMENT en JSON valide:
{{
  "likely_false_positive": true ou false,
  "fp_confidence": 0-100,
  "action_confidence": 0-100,
  "decision": "allow_auto_action" ou "block_auto_action",
  "reason": "raison courte en francais",
  "analyst_note": "note utile pour l analyste humain"
}}
"""

try:
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    body = {
        "model": GROQ_MODEL,
        "messages": [
            {
                "role": "system",
                "content": "Tu es un analyste SOC senior. Tu réponds uniquement en JSON valide. fp_confidence mesure la probabilité de faux positif. action_confidence mesure la certitude que l'action automatique est sûre. Ces deux valeurs sont indépendantes et ne peuvent pas se contredire avec likely_false_positive et decision."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"}
    }

    resp = requests.post(GROQ_API, headers=headers, json=body, timeout=30)

    if resp.status_code == 200:
        ai_text = resp.json()["choices"][0]["message"]["content"]
        ai = json.loads(ai_text)

        fp_confidence = int(ai.get("fp_confidence", 0))
        action_confidence = int(ai.get("action_confidence", 50))
        likely_fp = ai.get("likely_false_positive", False)
        decision = ai.get("decision", "block_auto_action")

        # ============= CONSISTENCY FIX =============
        # Rule 1: high fp_confidence always means block
        if fp_confidence > 60:
            likely_fp = True
            decision = "block_auto_action"

        # Rule 2: low action_confidence always means block
        if action_confidence <= 74:
            decision = "block_auto_action"

        # Rule 3: if FP is true, always block
        if likely_fp:
            decision = "block_auto_action"

        result["likely_false_positive"] = likely_fp
        result["fp_confidence"] = fp_confidence
        result["action_confidence"] = action_confidence
        result["decision"] = decision
        result["reason"] = ai.get("reason", "No reason provided")
        result["analyst_note"] = ai.get("analyst_note", "")

    else:
        result["error"] = f"Groq API error {resp.status_code}"
        result["decision"] = "block_auto_action"
        result["likely_false_positive"] = True
        result["fp_confidence"] = 100
        result["action_confidence"] = 0
        result["reason"] = "AI indisponible, blocage de l action automatique par securite"

except Exception as e:
    result["error"] = str(e)
    result["decision"] = "block_auto_action"
    result["likely_false_positive"] = True
    result["fp_confidence"] = 100
    result["action_confidence"] = 0
    result["reason"] = "AI FP check failed, blocage de l action automatique par securite"

print(json.dumps(result, default=str))