#!/usr/bin/env python3
"""
Score Calculator API - SOC-SOAR Project
========================================
Receives pre-fetched VT + OTX + Wazuh data from Shuffle.
Calculates a severity score (0-100) based on NIST SP 800-61.
Returns score + full evidence for TheHive alert.

Endpoints:
  POST /          -> Calculate score + return evidence
  POST /classify  -> Classify rule_id to playbook (router)
  GET  /health    -> Health check
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import logging
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

PORT = 9999


# ============================================================
#  SCORING FUNCTIONS (NIST SP 800-61 inspired)
# ============================================================

def calc_wazuh_score(level):
    try:
        level = int(level)
    except (ValueError, TypeError):
        return 0, "N/A"
    if level >= 13:
        return 20, f"Critical (level {level})"
    elif level >= 9:
        return 15, f"High (level {level})"
    elif level >= 5:
        return 10, f"Medium (level {level})"
    elif level >= 1:
        return 5, f"Low (level {level})"
    return 0, "None"


def calc_vt_score(malicious_count):
    try:
        malicious_count = int(malicious_count)
    except (ValueError, TypeError):
        return 0, "No data"
    if malicious_count > 20:
        return 20, f"Highly malicious ({malicious_count} engines)"
    elif malicious_count >= 6:
        return 15, f"Malicious ({malicious_count} engines)"
    elif malicious_count >= 1:
        return 8, f"Suspicious ({malicious_count} engines)"
    return 0, f"Clean ({malicious_count} engines)"


def calc_otx_score(pulse_count):
    try:
        pulse_count = int(pulse_count)
    except (ValueError, TypeError):
        return 0, "No data"
    if pulse_count > 5:
        return 20, f"High threat ({pulse_count} pulses)"
    elif pulse_count >= 3:
        return 15, f"Medium threat ({pulse_count} pulses)"
    elif pulse_count >= 1:
        return 8, f"Low threat ({pulse_count} pulses)"
    return 0, f"Unknown ({pulse_count} pulses)"


def calc_mitre_score(tactic):
    if not tactic or not isinstance(tactic, str):
        return 0, "No tactic"
    tactic_lower = tactic.lower()
    critical = ["privilege", "impact", "exfiltration"]
    high = ["credential", "execution", "command", "control"]
    medium = ["persistence", "lateral", "defense evasion"]
    low = ["reconnaissance", "discovery", "resource", "initial access"]
    for keyword in critical:
        if keyword in tactic_lower:
            return 20, f"Critical impact ({tactic})"
    for keyword in high:
        if keyword in tactic_lower:
            return 15, f"High impact ({tactic})"
    for keyword in medium:
        if keyword in tactic_lower:
            return 10, f"Medium impact ({tactic})"
    for keyword in low:
        if keyword in tactic_lower:
            return 5, f"Low impact ({tactic})"
    return 0, f"Unknown ({tactic})"


def calc_freq_score(firedtimes):
    try:
        firedtimes = int(firedtimes)
    except (ValueError, TypeError):
        return 0, "N/A"
    if firedtimes > 20:
        return 20, f"Very high ({firedtimes} times)"
    elif firedtimes >= 11:
        return 15, f"High ({firedtimes} times)"
    elif firedtimes >= 6:
        return 10, f"Medium ({firedtimes} times)"
    elif firedtimes >= 3:
        return 5, f"Low ({firedtimes} times)"
    return 0, f"Very low ({firedtimes} times)"


def get_severity(score):
    if score >= 75:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 25:
        return "medium"
    return "low"


def get_thehive_severity(severity):
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 1)


def get_recommended_action(severity):
    actions = {
        "critical": "BLOCK IP for 6 hours + Urgent alert to SOC team",
        "high": "BLOCK IP for 1 hour + Notify analyst",
        "medium": "Email analyst for review",
        "low": "Info ticket only - no action required"
    }
    return actions.get(severity, "No action")


# ============================================================
#  ROUTER CLASSIFIER
# ============================================================

def classify_rule(rule_id):
    """Map Wazuh rule_id to alert_type + playbook"""
    rule_id = str(rule_id)
    
    bruteforce_rules = ['5712', '5763', '5710', '5716', '100203', '40111']
    malware_rules = ['553', '550', '554', '510', '511', '512']
    
    # Suspicious activities → semi-auto (analyst review)
    suspicious_rules = [
            '60109',  # Windows: User account enabled or created (EventID 4720, 4722)
            '60110',  # Windows: User account changed (EventID 4738)
            '60111',  # Windows: User account disabled or deleted (EventID 4726)
            '60112',  # Windows: User added to group
            '60160',  # Domain users group changed (NOUVEAU)
            '60106',  # Windows: Suspicious PowerShell
            '60154',
            '60170',
            '5402',   # Linux: Successful sudo to root
            '5403',   # Linux: Failed sudo
            '40101',  # Nmap scan detection
            '92031',  # Discovery activity
            '92027',  # PowerShell spawned PowerShell
            '92066',  # Suspicious binary launched by PowerShell
            '92205',  # PowerShell created executable
            '92213',  # Executable dropped in suspicious folder
            '92021',  # PowerShell deleted files
        ]
    
    if rule_id in bruteforce_rules:
        return "bruteforce", "block_ip"
    elif rule_id in malware_rules:
        return "malware", "isolate_agent"
    elif rule_id in suspicious_rules:
        return "suspicious", "analyst_review"
    else:
        return "unknown", "log_only"

# ============================================================
#  BUILD EVIDENCE REPORT
# ============================================================

def build_evidence_report(data, scores, total, severity, action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    srcip = data.get('srcip', 'N/A')
    sha256 = data.get('sha256_after', data.get('sha256', 'N/A'))
    
    vt_link = f"https://www.virustotal.com/gui/ip-address/{srcip}" if srcip != 'N/A' else \
              f"https://www.virustotal.com/gui/file/{sha256}" if sha256 != 'N/A' else 'N/A'
    otx_link = f"https://otx.alienvault.com/indicator/ip/{srcip}" if srcip != 'N/A' else \
               f"https://otx.alienvault.com/indicator/file/{sha256}" if sha256 != 'N/A' else 'N/A'

    report = (
        f"============================================================\n"
        f"  SOC-SOAR AUTOMATED ANALYSIS REPORT\n"
        f"  Generated: {timestamp}\n"
        f"============================================================\n"
        f"\n"
        f">> ALERT INFO\n"
        f"   Rule ID     : {data.get('rule_id', 'N/A')}\n"
        f"   Description : {data.get('description', 'N/A')}\n"
        f"   Agent       : {data.get('agent', 'N/A')}\n"
        f"   Source IP   : {srcip}\n"
        f"   SHA256      : {sha256}\n"
        f"   Playbook    : {data.get('playbook', 'N/A')}\n"
        f"\n"
        f">> THREAT INTELLIGENCE\n"
        f"   VirusTotal  : {scores['vt_detail']}\n"
        f"   VT Link     : {vt_link}\n"
        f"   OTX         : {scores['otx_detail']}\n"
        f"   OTX Link    : {otx_link}\n"
        f"   MITRE ATT&CK: {scores['mitre_detail']}\n"
        f"\n"
        f">> SCORING BREAKDOWN\n"
        f"   Factor            | Score | Detail\n"
        f"   ------------------+-------+---------------------------\n"
        f"   Wazuh Level       | {scores['wazuh_score']:>5} | {scores['wazuh_detail']}\n"
        f"   VirusTotal        | {scores['vt_score']:>5} | {scores['vt_detail']}\n"
        f"   OTX AlienVault    | {scores['otx_score']:>5} | {scores['otx_detail']}\n"
        f"   MITRE ATT&CK      | {scores['mitre_score']:>5} | {scores['mitre_detail']}\n"
        f"   Frequency         | {scores['freq_score']:>5} | {scores['freq_detail']}\n"
        f"   Bonus (3+ high)   | {scores['bonus']:>5} |\n"
        f"   ------------------+-------+---------------------------\n"
        f"   TOTAL             | {total:>5} | Severity: {severity.upper()}\n"
        f"\n"
        f">> RECOMMENDED ACTION\n"
        f"   {action}\n"
        f"\n"
        f"============================================================"
    )
    report = report.replace('\n', '\\n')
    return report


# ============================================================
#  HTTP HANDLER
# ============================================================

class ScoreHandler(BaseHTTPRequestHandler):

    def _send_json(self, code, payload):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {
                "status": "ok",
                "service": "score-api",
                "port": PORT
            })
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            data = json.loads(body) if body else {}

            # === /classify endpoint (router) ===
            if self.path == "/classify":
                rule_id = str(data.get('rule_id', ''))
                alert_type, playbook = classify_rule(rule_id)
                logger.info(f"Classify: rule_id={rule_id} -> {alert_type} ({playbook})")
                self._send_json(200, {
                    "type": alert_type,
                    "playbook": playbook,
                    "rule_id": rule_id
                })
                return

            # === / endpoint (score calculator) ===
            logger.info(f"Received: {json.dumps(data)}")

            wazuh_level = data.get("level", 0)
            playbook = data.get("playbook", "")
            
            # Pick correct VT/OTX values based on playbook
            if playbook == "isolate_agent":  # malware scenario
                vt_malicious = data.get("vt_malicious_hash", 0) or 0
                otx_pulses = data.get("otx_pulses_hash", 0) or 0
            else:  # block_ip scenario
                vt_malicious = data.get("vt_malicious_ip", 0) or 0
                otx_pulses = data.get("otx_pulses_ip", 0) or 0
            mitre_tactic = data.get("tactic", "")
            firedtimes = data.get("firedtimes", 0)

            w_score, w_detail = calc_wazuh_score(wazuh_level)
            v_score, v_detail = calc_vt_score(vt_malicious)
            o_score, o_detail = calc_otx_score(otx_pulses)
            m_score, m_detail = calc_mitre_score(mitre_tactic)
            f_score, f_detail = calc_freq_score(firedtimes)

            total = w_score + v_score + o_score + m_score + f_score
            factors = [w_score, v_score, o_score, m_score, f_score]
            bonus = 5 if sum(1 for f in factors if f >= 15) >= 3 else 0
            total = min(total + bonus, 100)

            severity = get_severity(total)
            thehive_severity = get_thehive_severity(severity)
            action = get_recommended_action(severity)

            scores = {
                "wazuh_score": w_score, "wazuh_detail": w_detail,
                "vt_score": v_score, "vt_detail": v_detail,
                "otx_score": o_score, "otx_detail": o_detail,
                "mitre_score": m_score, "mitre_detail": m_detail,
                "freq_score": f_score, "freq_detail": f_detail,
                "bonus": bonus
            }

            evidence_report = build_evidence_report(data, scores, total, severity, action)

            result = {
                "score": total,
                "severity": severity,
                "thehive_severity": thehive_severity,
                "recommended_action": action,
                "evidence_report": evidence_report,
                "details": {
                    "wazuh": {"score": w_score, "detail": w_detail},
                    "vt": {"score": v_score, "detail": v_detail},
                    "otx": {"score": o_score, "detail": o_detail},
                    "mitre": {"score": m_score, "detail": m_detail},
                    "freq": {"score": f_score, "detail": f_detail},
                    "bonus": bonus
                }
            }

            logger.info(f"Score: {total} | Severity: {severity} | IP: {data.get('srcip', '?')}")
            self._send_json(200, result)

        except Exception as e:
            logger.error(f"Error: {e}")
            self._send_json(500, {
                "error": str(e),
                "score": 0,
                "severity": "low",
                "thehive_severity": 1,
                "recommended_action": "Error in scoring - manual review required",
                "evidence_report": f"ERROR: {str(e)}"
            })

    def log_message(self, format, *args):
        pass


# ============================================================
#  MAIN
# ============================================================

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), ScoreHandler)
    logger.info(f"Score API running on port {PORT}")
    logger.info(f"Endpoints:")
    logger.info(f"  POST /         -> Calculate score")
    logger.info(f"  POST /classify -> Router (rule_id -> playbook)")
    logger.info(f"  GET  /health   -> Health check")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.server_close()
