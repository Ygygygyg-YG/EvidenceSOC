from evidencesoc.main import app
from fastapi.testclient import TestClient


def test_live_health() -> None:
    response = TestClient(app).get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}