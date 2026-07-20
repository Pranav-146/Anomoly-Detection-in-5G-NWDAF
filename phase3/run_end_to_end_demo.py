"""End-to-end demo that connects the existing detector to the closed-loop controller."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SECURITY_LAYER_DIR = REPO_ROOT / "Security Layer"

if "" in sys.path:
    sys.path.remove("")
if str(SECURITY_LAYER_DIR) not in sys.path:
    sys.path.insert(0, str(SECURITY_LAYER_DIR))

from event_log import WindowEvent, generate_benign_sequence, generate_sustained_attack_sequence
from realtime_engine import SecurityLayerEngine

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from phase3.closed_loop_controller import ClosedLoopController
from phase3.detection_adapter import DetectionAdapter


def build_demo_events() -> list:
    benign = generate_benign_sequence("demo-benign", "cellA", num_windows=2, seed=5)
    attack = generate_sustained_attack_sequence("demo-attacker", "cellZ", num_windows=6, target_ratio=0.29)
    rule_event = WindowEvent(
        supi="demo-attacker",
        origin="cellZ",
        window_index=99,
        attempts=100,
        failures=40,
        timestamp=180.0,
    )
    return [benign[0], rule_event, *attack]


def main() -> None:
    controller = ClosedLoopController()
    engine = SecurityLayerEngine()
    adapter = DetectionAdapter(controller=controller, detector=engine)
    engine.detection_callback = adapter.handle_detector_result

    events = build_demo_events()

    print("=== End-to-End NWDAF Closed Loop Demo ===")
    print()

    for index, event in enumerate(events, start=1):
        print(f"Record processed {index}: {event.supi} @ t={event.timestamp}")
        print(f"ratio={event.raw_ratio:.3f} attempts={event.attempts} failures={event.failures}")
        print()
        adapter.process_event(event)
        print("-" * 60)

    summary = adapter.get_summary()
    print("Summary")
    print(f"Total records processed: {summary['total_records_processed']}")
    print(f"Rule detections: {summary['rule_detections']}")
    print(f"Isolation Forest detections: {summary['isolation_forest_detections']}")
    print(f"Combined detections: {summary['combined_detections']}")
    print(f"Total enforcement actions: {summary['total_enforcement_actions']}")

    output_path = REPO_ROOT / "phase3" / "end_to_end_demo_history.csv"
    controller.export_history_csv(output_path)
    print(f"Exported enforcement history to {output_path}")


if __name__ == "__main__":
    main()
