from fastapi.testclient import TestClient

from app.common.utils.url_analysis import inspect_url
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


def test_url_analysis_reports_opaque_campaign_tokens() -> None:
    response = client.post(
        "/api/v1/url/analyze",
        json={
            "url": (
                "https://waev-perks.com/cihwP5T16NU/"
                "VPg01gT3I2Vgb1EKllRUbea465?_t1794092503676"
            ),
            "lang": "en",
        },
    )

    assert response.status_code == 200
    result = response.json()["result"]
    assert result["verdict"] == "suspicious"
    assert result["score"] >= 20
    assert {reason["code"] for reason in result["reasons"]} >= {
        "OPAQUE_PATH_TOKEN",
        "TRACKING_PARAMETER",
    }


def test_url_analysis_reports_wave_typosquatting() -> None:
    response = client.post(
        "/api/v1/url/analyze",
        json={
            "url": (
                "https://waev-perks.com/cihwP5T16NU/"
                "VPg01gT3I2Vgb1EKllRUbea465?_t1794092503676"
            ),
            "lang": "en",
        },
    )

    assert response.status_code == 200
    result = response.json()["result"]
    assert result["verdict"] == "suspicious"
    assert result["score"] >= 50
    assert "TYPOSQUATTING" in {
        reason["code"] for reason in result["reasons"]
    }


def test_url_analysis_reports_african_brand_typosquatting() -> None:
    for url in (
        "https://moove-africa.com/login",
        "https://mixxx-money.com/verify",
        "https://togoocom.com/account",
    ):
        result_codes = {signal.code for signal in inspect_url(url)}
        assert "TYPOSQUATTING" in result_codes


def test_url_analysis_validates_input_length() -> None:
    response = client.post(
        "/api/v1/url/analyze",
        json={"url": "x" * 2049, "lang": "en"},
    )

    assert response.status_code == 422
    assert response.json()["success"] is False
