#!/usr/bin/env python3
"""
Decision API — SOC-SOAR
========================
PORT 9998

POST /alert            ← Shuffle sends scored alert, get back {id, url}
GET  /review/<id>      ← Analyst opens this URL in browser
POST /decision/<id>    ← Dashboard posts analyst choice
GET  /status/<id>      ← Shuffle polls until ready
POST /ai-reason        ← Proxies to Anthropic (needs ANTHROPIC_API_KEY env var)
GET  /health
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json, uuid, os, logging
from datetime import datetime
from urllib.request import urlopen, Request as UReq
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PORT       = 9998
HOST_URL   = os.environ.get("HOST_URL", f"http://localhost:{PORT}")
ANTH_KEY   = os.environ.get("ANTHROPIC_API_KEY", "")

# In-memory store  {id: {alert, decision, notes, created_at}}
store = {}


def load_dashboard_html():
    path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    with open(path, "r") as f:
        return f.read()


class Handler(BaseHTTPRequestHandler):

    def _json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code, html):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def _get_id(self):
        # path like /review/abc-123  →  "abc-123"
        parts = self.path.split("/")
        return parts[2] if len(parts) >= 3 else None

    # ── OPTIONS (CORS preflight) ──────────────────────────────────────────────
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # ── GET ───────────────────────────────────────────────────────────────────
    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"status": "ok", "port": PORT})

        elif self.path.startswith("/review/"):
            alert_id = self._get_id()
            entry = store.get(alert_id)
            if not entry:
                self._html(404, "<h2>Alert not found or expired.</h2>")
                return
            html = load_dashboard_html()
            # Inject alert data as a JS global
            html = html.replace(
                "/* __ALERT_DATA__ */",
                f"window.ALERT_DATA = {json.dumps(entry['alert'])};"
            )
            html = html.replace("/* __ALERT_ID__ */", f"window.ALERT_ID = '{alert_id}';")
            html = html.replace("/* __API_URL__ */",  f"window.API_URL = '{HOST_URL}';")
            self._html(200, html)

        elif self.path.startswith("/status/"):
            alert_id = self._get_id()
            entry = store.get(alert_id)
            if not entry:
                self._json(404, {"error": "not found"})
                return
            if entry.get("decision"):
                self._json(200, {
                    "ready":    True,
                    "action":   entry["decision"],
                    "notes":    entry.get("notes", ""),
                    "decided_at": entry.get("decided_at", "")
                })
            else:
                self._json(200, {"ready": False})
        else:
            self.send_response(404); self.end_headers()

    # ── POST ──────────────────────────────────────────────────────────────────
    def do_POST(self):

        # Shuffle sends scored alert → store it → return URL
        if self.path == "/alert":
            data = self._read_body()
            alert_id = str(uuid.uuid4())[:8]
            store[alert_id] = {
                "alert":      data,
                "decision":   None,
                "notes":      "",
                "created_at": datetime.now().isoformat()
            }
            review_url = f"{HOST_URL}/review/{alert_id}"
            logger.info(f"New alert {alert_id} → {review_url}")
            self._json(200, {"id": alert_id, "url": review_url})

        # Analyst submits decision from dashboard
        elif self.path.startswith("/decision/"):
            alert_id = self._get_id()
            if alert_id not in store:
                self._json(404, {"error": "not found"}); return
            data = self._read_body()
            store[alert_id]["decision"]   = data.get("action", "unknown")
            store[alert_id]["notes"]      = data.get("notes", "")
            store[alert_id]["decided_at"] = datetime.now().isoformat()
            logger.info(f"Decision for {alert_id}: {store[alert_id]['decision']}")
            self._json(200, {"ok": True})

        # Proxy to Anthropic — keeps API key server-side
        elif self.path == "/ai-reason":
            if not ANTH_KEY:
                self._json(200, {"text": ""}); return
            body = self._read_body()
            req = UReq(
                "https://api.anthropic.com/v1/messages",
                data=json.dumps({
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": 1000,
                    "system": (
                        "You are a senior SOC analyst AI in a SOAR platform. "
                        "Format your response with these exact bold section headers on their own lines:\n"
                        "**THREAT ASSESSMENT**\n**KEY INDICATORS**\n**CONFIDENCE**\n**ANALYST RECOMMENDATION**\n"
                        "Key indicators must be bullet points (- item). Be direct. No padding."
                    ),
                    "messages": [{"role": "user", "content": body.get("prompt", "")}]
                }).encode(),
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": ANTH_KEY,
                    "anthropic-version": "2023-06-01"
                },
                method="POST"
            )
            try:
                with urlopen(req, timeout=30) as r:
                    resp = json.loads(r.read())
                text = "".join(b.get("text","") for b in resp.get("content",[]))
                self._json(200, {"text": text})
            except Exception as e:
                self._json(200, {"text": f"AI error: {e}"})
        else:
            self.send_response(404); self.end_headers()

    def log_message(self, *_): pass


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    logger.info(f"Decision API on port {PORT}")
    logger.info(f"HOST_URL = {HOST_URL}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
