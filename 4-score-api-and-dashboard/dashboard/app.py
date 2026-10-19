import os
import hmac
import sqlite3
import json
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ── Playbook display names ─────────────────────────────────
PLAYBOOK_NAMES = {
    "block_ip":       "Block IP",
    "isolate_agent":  "Quarantine File",
    "analyst_review": "Analyst Review",
    "log_only":       "Log Only",
}

@app.template_filter("playbook_label")
def playbook_label(value):
    return PLAYBOOK_NAMES.get(value, value or "—")

def require_secret(name, placeholder):
    """Read a secret from the environment. Refuse to start on a known default."""
    value = os.getenv(name, "")
    if not value or value == placeholder:
        raise RuntimeError(
            f"{name} is not set (or still holds the placeholder '{placeholder}').\n"
            f"Fix it in the dashboard .env file, for example:\n"
            f"    python3 -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
    return value


app.secret_key = require_secret("DASHBOARD_SECRET_KEY", "change_me")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

DB_PATH = os.path.join(os.path.dirname(__file__), "alerts.db")
SHUFFLE_APPROVAL_WEBHOOK = os.getenv("SHUFFLE_APPROVAL_WEBHOOK", "")

# Optional shared secret for the alert ingest endpoint. When empty the endpoint
# stays open (lab default). Set it in .env to require the X-Ingest-Token header.
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "")

ANALYST_USERNAME = os.getenv("ANALYST_USERNAME", "analyst")
ANALYST_PASSWORD = require_secret("ANALYST_PASSWORD", "change_me")

# ------------------------------------------------------------------
# DB init
# ------------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id         TEXT,
            source_ref          TEXT,
            thehive_alert_id    TEXT,
            playbook            TEXT,
            agent_id            TEXT,
            agent_name          TEXT,
            rule_id             TEXT,
            rule_description    TEXT,
            srcip               TEXT,
            sha256              TEXT,
            score               TEXT,
            severity            TEXT,
            ai_decision         TEXT,
            ai_confidence       INTEGER,
            ai_reason           TEXT,
            ai_summary          TEXT,
            ai_threat_level     TEXT,
            recommended_action  TEXT,
            status              TEXT DEFAULT 'pending',
            analyst_decision    TEXT,
            analyst_comment     TEXT,
            created_at          TEXT,
            decided_at          TEXT
        )
    """)
    try:
        c.execute("ALTER TABLE alerts ADD COLUMN incident_id TEXT")
    except Exception:
        pass
    conn.commit()
    conn.close()

init_db()

# ------------------------------------------------------------------
# Auth helpers
# ------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ------------------------------------------------------------------
# Auth routes
# ------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == ANALYST_USERNAME and password == ANALYST_PASSWORD:
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("index"))
        error = "Invalid credentials"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "soc-dashboard"})

# ------------------------------------------------------------------
# API: receive alert from Shuffle
# ------------------------------------------------------------------
@app.route("/api/alerts", methods=["POST"])
def create_alert():
    # Optional shared secret. Disabled while INGEST_TOKEN is empty (lab default).
    if INGEST_TOKEN:
        supplied = request.headers.get("X-Ingest-Token", "")
        if not hmac.compare_digest(supplied, INGEST_TOKEN):
            return jsonify({"error": "Invalid or missing X-Ingest-Token"}), 401

    data = request.get_json(silent=True)
    if not data:
        raw = request.get_data(as_text=True)
        try:
            import json as _json
            data = _json.loads(raw) if raw else {}
        except Exception:
            data = request.form.to_dict() or {}
    if not data:
        data = {}

    ai_confidence = data.get("ai_confidence")
    try:
        ai_confidence = int(ai_confidence) if ai_confidence not in (None, "", "null") else None
    except (ValueError, TypeError):
        ai_confidence = None

    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    playbook    = data.get("playbook", "")
    agent_id    = data.get("agent_id", "")
    thehive_id  = data.get("thehive_alert_id", "")

    # ── Incident grouping for analyst_review ──────────────────
    incident_id = None
    if playbook == "analyst_review":
        conn = get_db()
        existing = conn.execute("""
            SELECT incident_id FROM alerts
            WHERE playbook = 'analyst_review'
              AND agent_id = ?
              AND status IN ('pending', 'investigating')
              AND datetime(created_at) >= datetime(?, '-5 minutes')
            ORDER BY created_at DESC LIMIT 1
        """, (agent_id, created_at)).fetchone()
        conn.close()

        if existing and existing["incident_id"]:
            incident_id = existing["incident_id"]
        elif thehive_id:
            incident_id = f"INC-{thehive_id}"
        else:
            incident_id = f"INC-{agent_id}-{datetime.utcnow().strftime('%Y%m%d%H%M')}"

    # ai_summary for analyst_review comes as a full JSON object from Shuffle
    # We store it as a JSON string so we can parse events_detail later
    ai_summary = data.get("ai_summary")
    if isinstance(ai_summary, dict):
        ai_summary = json.dumps(ai_summary)

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO alerts (
            incident_id, source_ref, thehive_alert_id, playbook,
            agent_id, agent_name, rule_id, rule_description,
            srcip, sha256, score, severity,
            ai_decision, ai_confidence, ai_reason,
            ai_summary, ai_threat_level, recommended_action,
            status, created_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        incident_id,
        data.get("sourceRef"), data.get("thehive_alert_id"), playbook,
        agent_id, data.get("agent_name"), data.get("rule_id"), data.get("rule_description"),
        data.get("srcip"), data.get("sha256"), data.get("score"), data.get("severity"),
        data.get("ai_decision"), ai_confidence, data.get("ai_reason"),
        ai_summary, data.get("ai_threat_level"), data.get("recommended_action"),
        "pending", created_at
    ))
    conn.commit()
    alert_id = c.lastrowid
    conn.close()

    return jsonify({"status": "created", "id": alert_id, "incident_id": incident_id}), 201

# ------------------------------------------------------------------
# API: list alerts
# ------------------------------------------------------------------
@app.route("/api/alerts", methods=["GET"])
@login_required
def list_alerts():
    status_filter = request.args.get("status")
    conn = get_db()
    if status_filter:
        rows = conn.execute("SELECT * FROM alerts WHERE status=? ORDER BY created_at DESC", (status_filter,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ------------------------------------------------------------------
# API: get single alert + siblings
# ------------------------------------------------------------------
@app.route("/api/alerts/<int:alert_id>", methods=["GET"])
@login_required
def get_alert(alert_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    alert = dict(row)
    siblings = []
    if alert.get("incident_id"):
        sibs = conn.execute(
            "SELECT * FROM alerts WHERE incident_id=? AND id!=? ORDER BY created_at ASC",
            (alert["incident_id"], alert_id)
        ).fetchall()
        siblings = [dict(s) for s in sibs]
    conn.close()
    alert["siblings"] = siblings
    return jsonify(alert)

# ------------------------------------------------------------------
# API: analyst decision
# ------------------------------------------------------------------
@app.route("/api/alerts/<int:alert_id>/decision", methods=["POST"])
@login_required
def make_decision(alert_id):
    data = request.get_json(silent=True) or {}
    decision = data.get("decision")
    comment  = data.get("comment", "")

    valid_decisions = ["approve_block_ip", "approve_quarantine", "isolate_agent", "reject", "mark_investigating"]
    if decision not in valid_decisions:
        return jsonify({"error": f"Invalid decision. Must be one of: {valid_decisions}"}), 400

    decided_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    status_map = {
        "approve_block_ip":   "approved",
        "approve_quarantine": "approved",
        "isolate_agent":      "approved",
        "reject":             "rejected",
        "mark_investigating": "investigating"
    }
    new_status = status_map[decision]

    conn = get_db()
    row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Not found"}), 404

    if row["incident_id"] and decision in ("isolate_agent", "reject", "mark_investigating"):
        conn.execute("""
            UPDATE alerts SET analyst_decision=?, analyst_comment=?, status=?, decided_at=?
            WHERE incident_id=? AND status IN ('pending','investigating')
        """, (decision, comment, new_status, decided_at, row["incident_id"]))
    else:
        conn.execute("""
            UPDATE alerts SET analyst_decision=?, analyst_comment=?, status=?, decided_at=?
            WHERE id=?
        """, (decision, comment, new_status, decided_at, alert_id))

    conn.commit()
    conn.close()

    shuffle_decisions = {"approve_block_ip", "approve_quarantine", "isolate_agent"}
    if SHUFFLE_APPROVAL_WEBHOOK and decision in shuffle_decisions:
        shuffle_decision = decision
        try:
            payload = {
                "dashboard_alert_id": alert_id,
                "decision": shuffle_decision,
                "agent_id": row["agent_id"],
                "srcip": row["srcip"],
                "sha256": row["sha256"],
                "playbook": row["playbook"],
                "comment": comment
            }
            resp = requests.post(SHUFFLE_APPROVAL_WEBHOOK, json=payload, timeout=5)
            resp.raise_for_status()
        except Exception as e:
            print(f"[WARN] Shuffle webhook failed: {e}")

    return jsonify({"status": "ok", "new_status": new_status})

# ------------------------------------------------------------------
# UI: index
# ------------------------------------------------------------------
@app.route("/")
@login_required
def index():
    conn = get_db()
    all_alerts = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC").fetchall()

    seen_incidents = set()
    display_alerts = []
    for a in all_alerts:
        a = dict(a)
        if a["playbook"] == "analyst_review" and a.get("incident_id"):
            if a["incident_id"] not in seen_incidents:
                seen_incidents.add(a["incident_id"])
                count = conn.execute(
                    "SELECT COUNT(*) FROM alerts WHERE incident_id=?", (a["incident_id"],)
                ).fetchone()[0]
                a["event_count"] = count
                display_alerts.append(a)
        else:
            a["event_count"] = 1
            display_alerts.append(a)

    stats = {
        "total":         conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "pending":       conn.execute("SELECT COUNT(*) FROM alerts WHERE status='pending'").fetchone()[0],
        "approved":      conn.execute("SELECT COUNT(*) FROM alerts WHERE status='approved'").fetchone()[0],
        "rejected":      conn.execute("SELECT COUNT(*) FROM alerts WHERE status='rejected'").fetchone()[0],
        "investigating": conn.execute("SELECT COUNT(*) FROM alerts WHERE status='investigating'").fetchone()[0],
        "critical":      conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='critical'").fetchone()[0],
        "high":          conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='high'").fetchone()[0],
    }
    conn.close()
    return render_template("index.html", alerts=display_alerts, stats=stats, username=session.get("username"))

# ------------------------------------------------------------------
# UI: alert detail — extracts events_detail from ai_summary
# ------------------------------------------------------------------
@app.route("/alert/<int:alert_id>")
@login_required
def alert_detail(alert_id):
    conn = get_db()
    alert = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        return "Alert not found", 404
    alert = dict(alert)

    siblings = []
    if alert.get("incident_id"):
        sibs = conn.execute(
            "SELECT * FROM alerts WHERE incident_id=? AND id!=? ORDER BY created_at ASC",
            (alert["incident_id"], alert_id)
        ).fetchall()
        siblings = [dict(s) for s in sibs]
    conn.close()

    # ── Extract events_detail and extra AI fields from ai_summary ──
    ai_chain_events = []
    ai_extra = {}
    if alert.get("ai_summary"):
        try:
            raw = alert["ai_summary"]
            parsed = json.loads(raw) if isinstance(raw, str) else raw
            if isinstance(parsed, dict):
                ai_chain_events = parsed.get("events_detail", [])
                ai_extra = {
                    "attack_pattern":      parsed.get("attack_pattern", ""),
                    "chain_detected":      parsed.get("chain_detected", False),
                    "events_correlated":   parsed.get("events_correlated", 0),
                    "analyst_priority":    parsed.get("analyst_priority", ""),
                    "mitre_tactics":       parsed.get("mitre_tactics_observed", []),
                    "recommended_actions": parsed.get("recommended_actions", []),
                    "summary":             parsed.get("summary", alert["ai_summary"]),
                }
                # Replace stored summary with parsed clean summary
                alert["ai_summary"] = ai_extra["summary"]
        except Exception:
            pass

    return render_template(
        "alert_detail.html",
        alert=alert,
        siblings=siblings,
        ai_chain_events=ai_chain_events,
        ai_extra=ai_extra,
        username=session.get("username")
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
