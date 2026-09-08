from fastapi.testclient import TestClient

from agent_guard_eval.api import create_app


def test_health() -> None:
    response = TestClient(create_app()).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_rejects_blank_input() -> None:
    response = TestClient(create_app()).post("/v1/analyze", json={"text": "   "})
    assert response.status_code == 422


def test_analyze_does_not_echo_raw_text() -> None:
    input_text = "harmless-private-value"
    response = TestClient(create_app()).post("/v1/analyze", json={"text": input_text})
    assert response.status_code == 200
    assert input_text not in response.text
