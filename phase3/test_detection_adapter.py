import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SECURITY_LAYER_DIR = REPO_ROOT / "Security Layer"

if "" in sys.path:
    sys.path.remove("")
if str(SECURITY_LAYER_DIR) not in sys.path:
    sys.path.insert(0, str(SECURITY_LAYER_DIR))

from event_log import WindowEvent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from phase3.closed_loop_controller import ClosedLoopController, EnforcementAction
from phase3.detection_adapter import DetectionAdapter


class FakeDetector:
    def __init__(self):
        self.detection_callback = None

    def process_event(self, event, now=None):
        result = {
            "candidate": True,
            "tier1": {"tier1_candidate": True},
            "tier2": {"tier2_candidate": True, "score": 0.71},
            "supi": event.supi,
        }
        if self.detection_callback is not None:
            self.detection_callback(event, result)
        return result


class DetectionAdapterTests(unittest.TestCase):
    def test_adapter_converts_detector_result_and_forwards_to_controller(self):
        controller = ClosedLoopController()
        detector = FakeDetector()
        adapter = DetectionAdapter(controller=controller, detector=detector)
        detector.detection_callback = adapter.handle_detector_result

        event = WindowEvent(
            supi="imsi-1001",
            origin="cellZ",
            window_index=3,
            attempts=80,
            failures=32,
            timestamp=90.0,
        )

        adapter.process_event(event)

        self.assertEqual(len(controller.get_history()), 1)
        decision = controller.get_history()[0]
        self.assertEqual(decision.action, EnforcementAction.LOG_ONLY)
        self.assertEqual(decision.supi, "imsi-1001")
        self.assertEqual(decision.detection_source, "BOTH")
        self.assertEqual(adapter.get_summary()["combined_detections"], 1)
        self.assertEqual(adapter.get_summary()["total_records_processed"], 1)


if __name__ == "__main__":
    unittest.main()
