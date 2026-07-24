"""Closed-loop enforcement controller for NWDAF detection events.

This module intentionally implements the insecure baseline policy described in
Phase 3: every detection event immediately results in a simulated session
release. It is designed to be independent from the Isolation Forest
implementation and any other detection logic.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional


@dataclass(frozen=True)
class DetectionEvent:
    """A single detection event emitted by the upstream detection stage."""

    timestamp: float
    supi: str
    detection_source: str
    anomaly_score: Optional[float] = None
    rule_triggered: bool = False
    if_triggered: bool = False
    reason: Optional[str] = None


class EnforcementAction(str, Enum):
    """Simple actions that the controller can emit for a detection event."""

    NONE = "NONE"
    LOG_ONLY = "LOG_ONLY"
    STEP_UP_AUTH = "STEP_UP_AUTH"
    THROTTLE = "THROTTLE"
    SESSION_RELEASE = "SESSION_RELEASE"


@dataclass(frozen=True)
class EnforcementDecision:
    """A decision emitted by the closed-loop controller."""

    timestamp: float
    supi: str
    action: EnforcementAction
    reason: str
    confidence: float
    source: str
    detection_source: str = "UNKNOWN"


class ClosedLoopController:
    """Lab-safe closed-loop controller that defaults to audit-only decisions."""

    def __init__(self, source_name: str = "CLOSED_LOOP_CONTROLLER",
                 default_action: EnforcementAction = EnforcementAction.LOG_ONLY,
                 history_csv_path: Optional[str | Path] = None) -> None:
        self._source_name = source_name
        self._default_action = default_action
        self._history_csv_path = Path(history_csv_path) if history_csv_path else None
        self._history: List[EnforcementDecision] = []

    def process_detection(self, event: DetectionEvent) -> EnforcementDecision:
        """Apply a safe lab-mode policy by default and allow opt-in release."""

        if event is None:
            return EnforcementDecision(
                timestamp=0.0,
                supi="",
                action=EnforcementAction.NONE,
                reason="No detection event supplied",
                confidence=0.0,
                source=self._source_name,
            )

        action = self._default_action
        reason = (
            event.reason
            or "Detection event received; logging only in lab-safe mode"
        )
        confidence = 0.85 if action == EnforcementAction.LOG_ONLY else 1.0

        if action == EnforcementAction.SESSION_RELEASE:
            reason = (
                event.reason
                or "Detection event received; session release permitted by configuration"
            )

        decision = EnforcementDecision(
            timestamp=event.timestamp,
            supi=event.supi,
            action=action,
            reason=reason,
            confidence=confidence,
            source=self._source_name,
            detection_source=event.detection_source,
        )
        self._history.append(decision)
        self._append_history_csv(decision)
        return decision

    def get_history(self) -> List[EnforcementDecision]:
        """Return a copy of the enforcement history."""

        return list(self._history)

    def clear_history(self) -> None:
        """Clear the in-memory enforcement history."""

        self._history.clear()

    def _append_history_csv(self, decision: EnforcementDecision) -> None:
        if self._history_csv_path is None:
            return

        self._history_csv_path.parent.mkdir(parents=True, exist_ok=True)
        file_exists = self._history_csv_path.exists()
        with self._history_csv_path.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["timestamp", "supi", "action", "detection_source", "reason"],
            )
            if not file_exists:
                writer.writeheader()
            writer.writerow(
                {
                    "timestamp": decision.timestamp,
                    "supi": decision.supi,
                    "action": decision.action.value,
                    "detection_source": decision.detection_source,
                    "reason": decision.reason,
                }
            )

    def export_history_csv(self, path: str | Path) -> None:
        """Export enforcement history to a CSV file with the requested columns."""

        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["timestamp", "supi", "action", "detection_source", "reason"],
            )
            writer.writeheader()
            for decision in self._history:
                writer.writerow(
                    {
                        "timestamp": decision.timestamp,
                        "supi": decision.supi,
                        "action": decision.action.value,
                        "detection_source": decision.detection_source,
                        "reason": decision.reason,
                    }
                )
