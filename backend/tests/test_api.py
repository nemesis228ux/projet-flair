import json
import logging

from fastapi.testclient import TestClient
import pytest

from app.main import app

client = TestClient(app)


def test_health_response_uses_api_wrapper() -> None:
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {
        "success": True,
        "result": {"status": "ok"},
        "error": None,
    }


def test_url_analysis_uses_the_submitted_url_and_shared_wrapper() -> None:
    response = client.post(
        "/api/url/analyze",
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
        "/api/url/analyze",
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
        "/api/url/analyze",
        json={"url": "x" * 2049, "lang": "en"},
    )

    assert response.status_code == 422
    assert response.json()["success"] is False


def test_email_analysis_returns_mock_wrapper() -> None:
    response = client.post(
        "/api/email/analyze",
        json={"content": "Example email", "lang": "fr"},
    )

    assert response.status_code == 200
    assert response.json()["success"] is True
    assert response.json()["result"]["sources"] == ["stub"]


def test_password_check_returns_mock_wrapper() -> None:
    response = client.post(
        "/api/password/check",
        json={"password": "do-not-return-this", "lang": "en"},
    )

    assert response.status_code == 200
    assert response.json()["success"] is True
    assert response.json()["result"]["sources"] == ["stub"]
    assert "do-not-return-this" not in response.text


def test_password_is_not_returned_or_logged_on_validation_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "private-password-" + ("x" * 130)
    with caplog.at_level(logging.INFO):
        response = client.post(
            "/api/password/check",
            json={"password": secret, "lang": "en"},
        )

    assert response.status_code == 422
    assert response.json()["success"] is False
    assert secret not in json.dumps(response.json())
    assert secret not in caplog.text
