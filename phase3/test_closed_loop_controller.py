import csv
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from phase3.closed_loop_controller import (
    ClosedLoopController,
    DetectionEvent,
    EnforcementAction,
)


class ClosedLoopControllerTests(unittest.TestCase):
    def test_process_detection_returns_session_release(self) -> None:
        controller = ClosedLoopController()
        event = DetectionEvent(
            timestamp=100.0,
            supi="imsi-001",
            detection_source="RULE",
            anomaly_score=0.35,
            rule_triggered=True,
            if_triggered=False,
        )

        decision = controller.process_detection(event)

        self.assertEqual(decision.action, EnforcementAction.SESSION_RELEASE)
        self.assertEqual(decision.supi, "imsi-001")
        self.assertEqual(len(controller.get_history()), 1)

    def test_export_history_csv(self) -> None:
        controller = ClosedLoopController()
        event = DetectionEvent(
            timestamp=200.0,
            supi="imsi-002",
            detection_source="BOTH",
            anomaly_score=0.60,
            rule_triggered=True,
            if_triggered=True,
        )
        controller.process_detection(event)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "history.csv")
            controller.export_history_csv(path)
            with open(path, newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["supi"], "imsi-002")
        self.assertEqual(rows[0]["action"], "SESSION_RELEASE")


if __name__ == "__main__":
    unittest.main()
