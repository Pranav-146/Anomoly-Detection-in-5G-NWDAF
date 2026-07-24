"""Bridge from tester run results into the closed-loop detection engine."""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Optional

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SECURITY_LAYER_DIR = os.path.join(REPO_ROOT, "Security Layer")
for path in (SECURITY_LAYER_DIR, REPO_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from event_log import WindowEvent


class ClosedLoopBridge:
    """Convert a tester result into a WindowEvent and forward it into the engine."""

    def __init__(self, engine: Optional[Any] = None, adapter: Optional[Any] = None) -> None:
        self.engine = engine
        self.adapter = adapter

    def process_result(self, result: Any, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Inspect a test result and, if possible, forward a security event."""
        if self.engine is None:
            return {"forwarded": False, "reason": "no_engine"}

        details = getattr(result, "details", {}) or {}
        if params:
            details = {**params, **details}
        supi = self._extract_supi(details)
        if not supi:
            return {"forwarded": False, "reason": "no_supi"}

        event = WindowEvent(
            supi=str(supi),
            origin=str(details.get("origin", details.get("cell", "cellA"))),
            window_index=int(details.get("window_index", 0)),
            attempts=int(details.get("attempts", details.get("attempt_count", 1))),
            failures=int(details.get("failures", details.get("failure_count", 0))),
            timestamp=float(details.get("timestamp", time.time())),
        )

        processed = self.engine.process_event(event, now=event.timestamp)
        return {
            "forwarded": True,
            "supi": event.supi,
            "candidate": bool(processed.get("candidate")),
            "decision": None,
            "event": {
                "origin": event.origin,
                "window_index": event.window_index,
                "attempts": event.attempts,
                "failures": event.failures,
                "timestamp": event.timestamp,
            },
            "result": processed,
        }

    @staticmethod
    def _extract_supi(details: dict[str, Any]) -> Optional[str]:
        for key in ("supi", "imsi", "subscriber", "target_supi", "target_imsi"):
            value = details.get(key)
            if value:
                return str(value)
        return None
