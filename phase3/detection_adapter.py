"""Adapter that converts Stage 1 detector output into closed-loop events."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
SECURITY_LAYER_DIR = REPO_ROOT / "Security Layer"

if "" in sys.path:
    sys.path.remove("")
if str(SECURITY_LAYER_DIR) not in sys.path:
    sys.path.insert(0, str(SECURITY_LAYER_DIR))

from event_log import WindowEvent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from phase3.closed_loop_controller import ClosedLoopController, DetectionEvent


class DetectionAdapter:
    """Bridge between the existing detector and the closed-loop controller."""

    def __init__(self, controller: Optional[ClosedLoopController] = None,
                 detector: Optional[Any] = None) -> None:
        self.controller = controller or ClosedLoopController()
        self.detector = detector
        self.total_records_processed = 0
        self.rule_detections = 0
        self.if_detections = 0
        self.combined_detections = 0
        self.total_enforcement_actions = 0

    def attach_detector(self, detector: Any) -> "DetectionAdapter":
        self.detector = detector
        return self

    def process_event(self, event: WindowEvent, now: Optional[float] = None) -> dict[str, Any]:
        """Process a single detector event and forward any detection to the controller."""
        self.total_records_processed += 1
        if self.detector is None:
            raise RuntimeError("No detector attached to DetectionAdapter")
        return self.detector.process_event(event, now=now)

    def handle_detector_result(self, event: WindowEvent, result: dict[str, Any], now: Optional[float] = None) -> tuple[DetectionEvent, Any] | None:
        """Convert detector output into a DetectionEvent and forward it to the controller."""
        if not result.get("candidate"):
            return None

        detection_event = self._build_detection_event(event, result)
        self._update_statistics(detection_event)

        print("[Detection]")
        print(f"SUPI: {detection_event.supi}")
        print(f"Source: {detection_event.detection_source}")
        print(f"Score: {detection_event.anomaly_score}")
        print()

        decision = self.controller.process_detection(detection_event)
        self.total_enforcement_actions += 1

        print("[Closed Loop]")
        print(f"Decision: {decision.action.value}")
        print()

        return detection_event, decision

    def _build_detection_event(self, event: WindowEvent, result: dict[str, Any]) -> DetectionEvent:
        tier1_candidate = bool(result.get("tier1", {}).get("tier1_candidate", False))
        tier2_candidate = bool(result.get("tier2", {}).get("tier2_candidate", False))

        if tier1_candidate and tier2_candidate:
            detection_source = "BOTH"
        elif tier1_candidate:
            detection_source = "RULE"
        else:
            detection_source = "IF"

        tier2_score = result.get("tier2", {}).get("score")
        anomaly_score = max(float(event.raw_ratio), float(tier2_score or 0.0))

        reason_parts = []
        if tier1_candidate:
            reason_parts.append("Tier 1 hard rule triggered")
        if tier2_candidate:
            reason_parts.append("Tier 2 anomaly signal triggered")
        reason = "; ".join(reason_parts) if reason_parts else "Detection candidate raised"

        return DetectionEvent(
            timestamp=float(event.timestamp),
            supi=event.supi,
            detection_source=detection_source,
            anomaly_score=anomaly_score,
            rule_triggered=tier1_candidate,
            if_triggered=tier2_candidate,
            reason=reason,
        )

    def _update_statistics(self, event: DetectionEvent) -> None:
        if event.rule_triggered and event.if_triggered:
            self.combined_detections += 1
        elif event.rule_triggered:
            self.rule_detections += 1
        elif event.if_triggered:
            self.if_detections += 1

    def get_summary(self) -> dict[str, int]:
        return {
            "total_records_processed": self.total_records_processed,
            "rule_detections": self.rule_detections,
            "isolation_forest_detections": self.if_detections,
            "combined_detections": self.combined_detections,
            "total_enforcement_actions": self.total_enforcement_actions,
        }
