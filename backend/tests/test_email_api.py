from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_email_analysis_returns_mock_wrapper() -> None:
    response = client.post(
        "/api/email/analyze",
        json={"content": "Example email", "lang": "fr"},
    )

    assert response.status_code == 200
    assert response.json()["success"] is True
    assert response.json()["result"]["sources"] == ["stub"]
