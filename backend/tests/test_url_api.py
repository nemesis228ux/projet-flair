from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_url_analysis_uses_the_submitted_url_and_shared_wrapper() -> None:
    response = client.post(
        "/api/v1/url/analyze",
        json={"url": "https://example.com", "lang": "en"},
    )

    assert response.status_code == 200
    assert response.json()["success"] is True
    assert response.json()["result"] == {
        "score": 0,
        "verdict": "safe",
        "reasons": [],
        "sources": ["heuristics"],
        "tactics": None,
        "explanation": None,
        "breach_count": None,
    }


def test_url_analysis_reports_suspicious_url_signals() -> None:
    response = client.post(
        "/api/v1/url/analyze",
        json={"url": "http://paypa1-login.xyz/verify", "lang": "en"},
    )

    assert response.status_code == 200
    result = response.json()["result"]
    assert result["verdict"] == "dangerous"
    assert result["score"] >= 60
    assert {reason["code"] for reason in result["reasons"]} >= {
        "MISSING_HTTPS",
        "TYPOSQUATTING",
        "SUSPICIOUS_TLD",
        "SUSPICIOUS_KEYWORD",
    }


def test_url_analysis_validates_input_length() -> None:
    response = client.post(
        "/api/v1/url/analyze",
        json={"url": "x" * 2049, "lang": "en"},
    )

    assert response.status_code == 422
    assert response.json()["success"] is False
