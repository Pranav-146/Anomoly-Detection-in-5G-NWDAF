"""
_test_nwdaf_export_mock.py — LOCAL TEST-ONLY double for sa_core's real NWDAF
REST API. Unlike tester/tools/nwdaf_mock_server.py (which is a no-op stub
that doesn't persist anything), this one actually stores POSTed data points
and serves them back via /api/nwdaf/export, matching the real contract in
core/webservice/app/routes_nwdaf_analytics.go + core/nf/nwdaf/api.go.

Purpose: let us verify nwdaf_client.py's request/response handling end-to-end
today, without needing the full Docker/Go sa_core stack running. This is NOT
a replacement for testing against the real core — once the VM is up, point
NWDAFClientConfig.base_url at the real sa_core address instead and this file
is no longer needed.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import urllib.parse

PORT = 5000
STORE: list[dict] = []  # in-memory nwdaf_data_points equivalent


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # quiet

    def _reply(self, payload: dict, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def do_POST(self):
        if self.path != "/api/nwdaf/data":
            self._reply({"error": "not found"}, 404)
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self._reply({"error": "bad json"}, 400)
            return
        row = {
            "source_nf": body.get("source_nf", ""),
            "analytics_id": body.get("analytics_id", ""),
            "imsi": body.get("imsi", ""),
            "dnn": body.get("dnn", ""),
            "data_json": body.get("data_json", "{}"),
            "collected_at": body.get("collected_at", 0.0),
        }
        STORE.append(row)
        self._reply({"ok": True, "id": len(STORE)})

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/api/nwdaf/export":
            analytics_id = qs.get("analytics_id", [None])[0]
            imsi = qs.get("imsi", [None])[0]
            limit = int(qs.get("limit", [1000])[0])
            rows = [
                r for r in STORE
                if (not analytics_id or r["analytics_id"] == analytics_id)
                and (not imsi or r["imsi"] == imsi)
            ][:limit]
            self._reply({"ok": True, "analytics_id": analytics_id, "imsi": imsi, "rows": rows})
            return

        self._reply({"error": "not found"}, 404)


if __name__ == "__main__":
    server = HTTPServer(("", PORT), Handler)
    print(f"Test NWDAF export mock running on :{PORT} (real storage, unlike tester/tools/nwdaf_mock_server.py)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
