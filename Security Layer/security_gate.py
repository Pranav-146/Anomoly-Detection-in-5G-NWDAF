"""Decision Gate and policy automation for security escalation handling."""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class GateDecision:
    supi: str
    tier: str
    rule: str
    observed_ratio: float
    baseline_ratio: float
    excess_ratio: float
    reputation_score: float
    window_index: int
    timestamp_unix_ns: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["timestamp_unix_ns"] = self.timestamp_unix_ns
        return payload


class DecisionGate:
    """Two-layer decision gate with baseline filtering and reputation scoring."""

    def __init__(self, decay: float = 0.7, capped_contribution: float = 0.35,
                 re_challenge_threshold: float = 0.6, throttle_threshold: float = 0.8,
                 audit_log_path: str | None = None):
        self.decay = decay
        self.capped_contribution = capped_contribution
        self.re_challenge_threshold = re_challenge_threshold
        self.throttle_threshold = throttle_threshold
        self.audit_log_path = audit_log_path or os.path.join(
            os.path.dirname(__file__), "gate_audit.jsonl"
        )

    def evaluate_window(self, supi: str, observed_ratio: float, baseline_ratio: float,
                        window_index: int, existing_score: float = 0.0,
                        now_ns: int | None = None) -> GateDecision:
        now_ns = now_ns if now_ns is not None else time.time_ns()
        excess = max(0.0, observed_ratio - baseline_ratio)
        score = self.decay * existing_score + min(excess, self.capped_contribution)

        if score < self.re_challenge_threshold:
            tier = "re_challenge"
            rule = "single_suspicious_window"
            reason = "single-window excess above baseline; request limited verification"
        elif score < self.throttle_threshold:
            tier = "throttle"
            rule = "repeated_excess_across_windows"
            reason = "reputation score has crossed the throttle threshold"
        else:
            tier = "escalate"
            rule = "sustained_high_reputation"
            reason = "sustained excess and high reputation score justify escalation"

        decision = GateDecision(
            supi=supi,
            tier=tier,
            rule=rule,
            observed_ratio=observed_ratio,
            baseline_ratio=baseline_ratio,
            excess_ratio=excess,
            reputation_score=score,
            window_index=window_index,
            timestamp_unix_ns=now_ns,
            reason=reason,
        )
        self.append_audit(decision)
        return decision

    def append_audit(self, decision: GateDecision) -> None:
        os.makedirs(os.path.dirname(self.audit_log_path), exist_ok=True)
        with open(self.audit_log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(decision.to_dict()) + "\n")


class PolicyEngine:
    """Policy handler that validates, deduplicates, and enforces gate decisions."""

    def __init__(self, audit_log_path: str | None = None):
        self.audit_log_path = audit_log_path or os.path.join(
            os.path.dirname(__file__), "policy_audit.jsonl"
        )
        self._seen_exception_ids: set[str] = set()
        self._active_throttles: dict[str, int] = {}

    def handle_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        supi = (payload.get("supi") or "").strip()
        exception_id = (payload.get("exception_id") or "").strip()
        tier = (payload.get("tier") or "").strip()

        if not supi:
            return {"ok": False, "error": "missing SUPI"}
        if not exception_id:
            return {"ok": False, "error": "missing exception_id"}
        if tier not in {"re_challenge", "throttle", "escalate"}:
            return {"ok": False, "error": f"unknown tier: {tier}"}
        if exception_id in self._seen_exception_ids:
            return {"ok": False, "error": f"duplicate exception_id: {exception_id}"}

        self._seen_exception_ids.add(exception_id)
        t1 = time.time_ns()
        action = self._map_tier_to_action(tier)
        t2 = time.time_ns()
        self._record_enforcement(exception_id, supi, tier, action)
        t3 = time.time_ns()

        latency_ms = {
            "notification_to_decision": round((t2 - t1) / 1_000_000, 3),
            "decision_to_enforcement": round((t3 - t2) / 1_000_000, 3),
            "end_to_end": round((t3 - t1) / 1_000_000, 3),
        }

        return {
            "ok": True,
            "exception_id": exception_id,
            "action": action,
            "t1_received_unix_ns": t1,
            "t2_decision_unix_ns": t2,
            "t3_completed_unix_ns": t3,
            "latency_ms": latency_ms,
        }

    def _map_tier_to_action(self, tier: str) -> str:
        mapping = {
            "re_challenge": "reauthentication_challenge",
            "throttle": "admission_throttle",
            "escalate": "pdu_sessions_released",
        }
        return mapping[tier]

    def _record_enforcement(self, exception_id: str, supi: str, tier: str, action: str) -> None:
        os.makedirs(os.path.dirname(self.audit_log_path), exist_ok=True)
        record = {
            "exception_id": exception_id,
            "supi": supi,
            "tier": tier,
            "action": action,
            "timestamp_unix_ns": time.time_ns(),
        }
        with open(self.audit_log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
