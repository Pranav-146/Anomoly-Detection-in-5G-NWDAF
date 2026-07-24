from fastapi.testclient import TestClient

from tester.src.app import app


client = TestClient(app)


def test_closed_loop_process_route_accepts_live_event_payload():
    payload = {
        "supi": "imsi-demo-001",
        "origin": "cellA",
        "window_index": 7,
        "attempts": 50,
        "failures": 20,
        "timestamp": 180.0,
    }

    response = client.post("/api/closed-loop/process", json=payload)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is True
    assert "candidate" in body
    assert "decision" in body
