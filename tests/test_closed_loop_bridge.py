import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tester.src.closed_loop_bridge import ClosedLoopBridge


class DummyEngine:
    def __init__(self):
        self.events = []

    def process_event(self, event, now=None):
        self.events.append((event, now))
        return {"candidate": False}


class DummyAdapter:
    def __init__(self):
        self.last_decision = None

    def get_summary(self):
        return {"total_records_processed": 0}

    def handle_detector_result(self, event, result, now=None):
        return None


def test_closed_loop_bridge_forwards_supi_from_result_details():
    engine = DummyEngine()
    adapter = DummyAdapter()
    bridge = ClosedLoopBridge(engine=engine, adapter=adapter)

    result = SimpleNamespace(
        details={
            "supi": "imsi-demo-001",
            "origin": "cellA",
            "window_index": 3,
            "attempts": 40,
            "failures": 20,
            "timestamp": 123.0,
        }
    )

    output = bridge.process_result(result)

    assert output["forwarded"] is True
    assert len(engine.events) == 1
    event, now = engine.events[0]
    assert event.supi == "imsi-demo-001"
    assert event.window_index == 3
    assert now == 123.0


def test_closed_loop_bridge_uses_params_when_details_missing_supi():
    engine = DummyEngine()
    adapter = DummyAdapter()
    bridge = ClosedLoopBridge(engine=engine, adapter=adapter)

    result = SimpleNamespace(details={"origin": "cellB", "window_index": 2})

    output = bridge.process_result(result, params={"supi": "imsi-demo-002"})

    assert output["forwarded"] is True
    assert output["supi"] == "imsi-demo-002"
