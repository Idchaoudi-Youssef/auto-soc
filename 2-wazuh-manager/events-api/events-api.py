#!/usr/bin/env python3
"""
Events API - Expose Wazuh alerts.json for the SOAR pipeline
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import re

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
PORT = 8888

INTERESTING_RULES = {
    '60109', '60110', '60111', '60112', '60154', '60160', '60170',
    '60106', '60107',
    '5712', '5763', '5710', '5716',
    '553', '550', '554', '510', '511',
    '5402', '5403',
    '60125', '60145',
    '92021', '92027', '92031', '92057', '92066', '92205', '92213',
    '40101',
}


def get_recent_alerts(agent_id=None, limit=15, min_level=5, suspicious_only=False):
    if not os.path.exists(ALERTS_FILE):
        return []

    alerts = []
    with open(ALERTS_FILE, 'r') as f:
        f.seek(0, 2)
        size = f.tell()
        chunk_size = min(2000000, size)
        f.seek(size - chunk_size)
        data = f.read()

    lines = data.split('\n')
    lines = lines[1:] if len(lines) > 1 else lines

    for line in lines[::-1]:
        if not line.strip():
            continue
        try:
            alert = json.loads(line)
            if agent_id and alert.get('agent', {}).get('id') != agent_id:
                continue

            level = alert.get('rule', {}).get('level', 0)
            rule_id = str(alert.get('rule', {}).get('id', ''))
            mitre = alert.get('rule', {}).get('mitre', {})
            has_mitre = bool(mitre.get('tactic'))

            if level < min_level:
                continue
            if suspicious_only and rule_id not in INTERESTING_RULES and not has_mitre:
                continue

            alerts.append({
                'timestamp': alert.get('timestamp'),
                'rule_id': rule_id,
                'rule_level': level,
                'description': alert.get('rule', {}).get('description'),
                'mitre_tactic': mitre.get('tactic', []),
                'mitre_technique': mitre.get('technique', []),
                'agent': alert.get('agent', {}).get('name'),
                'srcip': alert.get('data', {}).get('srcip'),
                'eventdata': alert.get('data', {}).get('win', {}).get('eventdata', {}),
                'eventID': alert.get('data', {}).get('win', {}).get('system', {}).get('eventID'),
            })

            if len(alerts) >= limit:
                break
        except json.JSONDecodeError:
            continue

    return alerts


class EventsHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _get_query_param(self, name, default=None):
        if '?' not in self.path:
            return default
        query = self.path.split('?', 1)[1]
        for kv in query.split('&'):
            if '=' in kv:
                k, v = kv.split('=', 1)
                if k == name:
                    return v
        return default

    def _send_json(self, data, status=200):
        body = json.dumps(data, indent=2, default=str).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            if self.path == '/health':
                self._send_json({"status": "ok", "service": "events-api"})
                return

            m = re.match(r'^/agent/([^/]+)/recent(\?.*)?$', self.path)
            if m:
                agent_id = m.group(1)
                limit = int(self._get_query_param('limit', default=10))
                min_level = int(self._get_query_param('min_level', default=5))
                suspicious_only = self._get_query_param('suspicious_only', default='true') == 'true'
                alerts = get_recent_alerts(
                    agent_id=agent_id,
                    limit=limit,
                    min_level=min_level,
                    suspicious_only=suspicious_only,
                )
                self._send_json({
                    "agent_id": agent_id,
                    "count": len(alerts),
                    "filters": {"limit": limit, "min_level": min_level, "suspicious_only": suspicious_only},
                    "alerts": alerts,
                })
                return

            if self.path.startswith('/recent'):
                limit = int(self._get_query_param('limit', default=15))
                alerts = get_recent_alerts(limit=limit)
                self._send_json({"count": len(alerts), "alerts": alerts})
                return

            self._send_json({"error": "Not found"}, status=404)
        except Exception as e:
            self._send_json({"error": str(e)}, status=500)


if __name__ == "__main__":
    print(f"[events-api] Starting on port {PORT}")
    server = HTTPServer(('0.0.0.0', PORT), EventsHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[events-api] Stopped")
