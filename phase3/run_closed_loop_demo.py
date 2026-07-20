"""Run a simple demo of the closed-loop controller pipeline."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from phase3.closed_loop_controller import ClosedLoopController, DetectionEvent


def main() -> None:
    controller = ClosedLoopController()

    events = [
        DetectionEvent(
            timestamp=100.0,
            supi="imsi-0009",
            detection_source="RULE",
            anomaly_score=0.31,
            rule_triggered=True,
            if_triggered=False,
        ),
        DetectionEvent(
            timestamp=101.0,
            supi="imsi-0010",
            detection_source="IF",
            anomaly_score=0.49,
            rule_triggered=False,
            if_triggered=True,
        ),
        DetectionEvent(
            timestamp=102.0,
            supi="imsi-0013",
            detection_source="BOTH",
            anomaly_score=0.78,
            rule_triggered=True,
            if_triggered=True,
        ),
    ]

    print("Detection received")
    print("↓")
    for event in events:
        decision = controller.process_detection(event)
        print(f"Enforcement decision -> supi={decision.supi} action={decision.action.value}")

    print("↓")
    print("History")
    for decision in controller.get_history():
        print(f"- {decision.supi}: {decision.action.value} -> {decision.reason}")

    output_path = Path(__file__).resolve().parent / "closed_loop_demo_history.csv"
    controller.export_history_csv(output_path)
    print("↓")
    print(f"CSV export -> {output_path}")


if __name__ == "__main__":
    main()
