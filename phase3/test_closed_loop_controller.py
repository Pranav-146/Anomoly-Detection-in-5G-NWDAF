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
    def test_process_detection_defaults_to_log_only(self) -> None:
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

        self.assertEqual(decision.action, EnforcementAction.LOG_ONLY)
        self.assertEqual(decision.supi, "imsi-001")
        self.assertEqual(len(controller.get_history()), 1)

    def test_can_enable_session_release_when_configured(self) -> None:
        controller = ClosedLoopController(default_action=EnforcementAction.SESSION_RELEASE)
        event = DetectionEvent(
            timestamp=101.0,
            supi="imsi-002",
            detection_source="IF",
            anomaly_score=0.82,
            rule_triggered=False,
            if_triggered=True,
        )

        decision = controller.process_detection(event)

        self.assertEqual(decision.action, EnforcementAction.SESSION_RELEASE)
        self.assertEqual(decision.supi, "imsi-002")

    def test_writes_history_to_csv_when_path_is_provided(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "history.csv")
            controller = ClosedLoopController(history_csv_path=csv_path)
            event = DetectionEvent(
                timestamp=102.0,
                supi="imsi-003",
                detection_source="RULE",
                anomaly_score=0.41,
                rule_triggered=True,
                if_triggered=False,
            )

            controller.process_detection(event)

            with open(csv_path, newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["supi"], "imsi-003")
        self.assertEqual(rows[0]["action"], "LOG_ONLY")

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
        self.assertEqual(rows[0]["action"], "LOG_ONLY")


if __name__ == "__main__":
    unittest.main()
