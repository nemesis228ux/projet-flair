from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_response_uses_api_wrapper() -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {
        "success": True,
        "result": {"status": "ok"},
        "error": None,
    }
