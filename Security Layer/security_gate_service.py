"""Tiny HTTP service exposing the security gate policy endpoint."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from security_gate import PolicyEngine


class SecurityGateHandler(BaseHTTPRequestHandler):
    engine = PolicyEngine()

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/security/policy-decision":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")
            return

        token = self.headers.get("X-Policy-Token", "")
        if token != os.environ.get("SECURITY_GATE_TOKEN", "dev-token"):
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": false, "error": "unauthorized"}')
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length) if content_length else b"{}"
        try:
            payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"ok": false, "error": "invalid json"}')
            return

        response = self.engine.handle_request(payload if isinstance(payload, dict) else {})
        self.send_response(200 if response.get("ok") else 400)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return


def main() -> None:
    host = os.environ.get("SECURITY_GATE_HOST", "127.0.0.1")
    port = int(os.environ.get("SECURITY_GATE_PORT", "8765"))
    server = ThreadingHTTPServer((host, port), SecurityGateHandler)
    print(f"security gate service listening on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
