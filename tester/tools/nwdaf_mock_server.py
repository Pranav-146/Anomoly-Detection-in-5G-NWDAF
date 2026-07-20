#!/usr/bin/env python3
"""Lightweight mock NWDAF to accept datapoints and return simple analytics.

- POST /api/nwdaf/data accepts JSON and returns 200 OK.
- GET /api/nwdaf/analytics/ABNORMAL_BEHAVIOUR?imsi=...&window_sec=... returns a
  JSON payload with a `result.result` object containing `anomaly_detected`,
  `alert_count`, and `alerts`.

This mock uses simple rules:
- If experiment.attack_type == "naive_attacker" and target_ratio >= 0.31 -> detected
- Otherwise -> not detected

Use for local testing only.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import urllib.parse

PORT = 6000

class Handler(BaseHTTPRequestHandler):
    def _set_json(self, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

    def do_POST(self):
        if self.path != "/api/nwdaf/data":
            self._set_json(404)
            self.wfile.write(json.dumps({"error": "not found"}).encode())
            return
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length).decode("utf-8")
        try:
            payload = json.loads(data)
        except Exception:
            payload = {}
        # no-op store; echo success
        self._set_json(200)
        self.wfile.write(json.dumps({"status": "ok"}).encode())

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if not parsed.path.startswith("/api/nwdaf/analytics/ABNORMAL_BEHAVIOUR"):
            self._set_json(404)
            self.wfile.write(json.dumps({"error": "not found"}).encode())
            return
        qs = urllib.parse.parse_qs(parsed.query)
        imsi = qs.get("imsi", [None])[0]
        window_sec = int(qs.get("window_sec", [30])[0])
        # Simple fabricated result: no alerts by default
        result = {"anomaly_detected": False, "alert_count": 0, "alerts": []}
        # For demo, if an imsi contains digits we can't use, keep it simple
        # The ingest side encoded experiment info in the POST; in this mock we
        # can't access that easily, so simulate detection based on imsi pattern:
        # If imsi ends with a digit >= '5', pretend it's a naive high-ratio attack.
        try:
            if imsi and int(imsi[-1]) >= 5:
                result = {"anomaly_detected": True, "alert_count": 1, "alerts": [{"type": "HIGH_FAILURE_RATIO"}]}
        except Exception:
            pass
        payload = {"result": {"result": result}}
        self._set_json(200)
        self.wfile.write(json.dumps(payload).encode())


if __name__ == "__main__":
    server = HTTPServer(("", PORT), Handler)
    print(f"Mock NWDAF running on :{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
        print("Mock NWDAF stopped")
