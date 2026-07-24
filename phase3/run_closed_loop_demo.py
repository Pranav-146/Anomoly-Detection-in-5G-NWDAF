"""Run a simple demo of the closed-loop controller pipeline."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SECURITY_LAYER_DIR = REPO_ROOT / "Security Layer"

sys.path.append(str(REPO_ROOT))
sys.path.append(str(SECURITY_LAYER_DIR))

from realtime_engine import SecurityLayerEngine
from event_log import WindowEvent
from phase3.closed_loop_controller import ClosedLoopController, DetectionEvent


def main() -> None:
    controller = ClosedLoopController(history_csv_path=Path(__file__).resolve().parent / "closed_loop_demo_history.csv")
    engine = SecurityLayerEngine()

    print("=== Detection demo ===")
    flagged_event = WindowEvent(
        supi="demo-supi",
        origin="cellA",
        window_index=0,
        attempts=100,
        failures=30,
        timestamp=100.0,
    )
    result = engine.process_event(flagged_event, now=flagged_event.timestamp)
    print(f"Detection -> candidate={result['candidate']} reason={result['tier1']['reason']}")

    if result.get("candidate"):
        decision = controller.process_detection(
            DetectionEvent(
                timestamp=flagged_event.timestamp,
                supi=flagged_event.supi,
                detection_source="RULE",
                anomaly_score=flagged_event.raw_ratio,
                rule_triggered=True,
                if_triggered=False,
                reason="Tier 1 hard rule triggered",
            )
        )
        print(f"Closed-loop decision -> {decision.action.value} for {decision.supi}")

    blocked_id = "demo-supi"
    status_before = engine.is_currently_blocked(blocked_id, now=101.0)
    print(f"Blocked before reauth -> {status_before}")

    print("=== Step-up reauth demo ===")
    reauth_ok = engine.attempt_reauth(
        blocked_id,
        claimed_secret=b"correct-secret",
        real_secret=b"correct-secret",
        now=101.0,
    )
    print(f"Reauth result -> {reauth_ok}")
    status_after = engine.is_currently_blocked(blocked_id, now=102.0)
    print(f"Blocked after successful reauth -> {status_after}")

    print("=== History ===")
    for decision in controller.get_history():
        print(f"- {decision.supi}: {decision.action.value} -> {decision.reason}")


if __name__ == "__main__":
    main()
