import json
import logging

from fastapi.testclient import TestClient
import pytest

from app.common.app_result import GenericAppResult
from app.common.business_error import AppError, AppErrorType
from app.core.rate_limit import limiter
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_password_rate_limit() -> None:
    limiter.reset()


def test_password_check_returns_analysis_without_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def no_breach(
        _password: str,
    ) -> GenericAppResult[int, AppError]:
        return GenericAppResult.success(0)

    monkeypatch.setattr(
        "app.services.password_analysis_service.check_password_breach", no_breach
    )
    response = client.post(
        "/api/password/check",
        json={"password": "do-not-return-this", "lang": "en"},
    )

    assert response.status_code == 200
    assert response.json()["success"] is True
    assert response.json()["result"]["sources"] == ["zxcvbn", "hibp"]
    assert response.json()["result"]["breach_count"] == 0
    assert "do-not-return-this" not in response.text


def test_password_check_propagates_breach_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def found_breach(
        _password: str,
    ) -> GenericAppResult[int, AppError]:
        return GenericAppResult.success(12)

    monkeypatch.setattr(
        "app.services.password_analysis_service.check_password_breach",
        found_breach,
    )
    response = client.post(
        "/api/password/check",
        json={"password": "this-is-a-test-password", "lang": "en"},
    )

    assert response.status_code == 200
    result = response.json()["result"]
    assert result["score"] == 100
    assert result["verdict"] == "dangerous"
    assert result["breach_count"] == 12
    assert "BREACHED" in {reason["code"] for reason in result["reasons"]}


def test_password_check_returns_generic_error_when_hibp_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def unavailable(
        _password: str,
    ) -> GenericAppResult[int, AppError]:
        return GenericAppResult.failure(
            AppError(
                error_type=AppErrorType.UNKNOWN_ERROR,
                error_message="Temporary outage",
            )
        )

    monkeypatch.setattr(
        "app.services.password_analysis_service.check_password_breach",
        unavailable,
    )
    response = client.post(
        "/api/password/check",
        json={"password": "do-not-return-this", "lang": "en"},
    )

    assert response.status_code == 503
    assert response.json()["success"] is False
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


def test_strong_password_scores_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Un mot de passe zxcvbn score 3 ou 4 (fort / très fort) doit être classé SAFE,
    et non SUSPICIOUS comme le faisait l'ancienne formule linéaire.
    """
    async def no_breach(_password: str) -> GenericAppResult[int, AppError]:
        return GenericAppResult.success(0)

    monkeypatch.setattr(
        "app.services.password_analysis_service.check_password_breach", no_breach
    )
    # Mot de passe que zxcvbn note score=3 ou 4
    response = client.post(
        "/api/password/check",
        json={"password": "Tr0ub4dor&3-correct-horse", "lang": "fr"},
    )

    assert response.status_code == 200
    result = response.json()["result"]
    assert result["verdict"] == "safe", (
        f"Un mot de passe fort ne doit pas être SUSPICIOUS ; score={result['score']}"
    )
    assert result["score"] < 20


def test_breach_reason_detail_contains_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Le message de la raison BREACHED doit mentionner le nombre de fuites."""
    async def found_breach(_password: str) -> GenericAppResult[int, AppError]:
        return GenericAppResult.success(99)

    monkeypatch.setattr(
        "app.services.password_analysis_service.check_password_breach", found_breach
    )
    response = client.post(
        "/api/password/check",
        json={"password": "some-password", "lang": "fr"},
    )

    assert response.status_code == 200
    reasons = response.json()["result"]["reasons"]
    breached = next(r for r in reasons if r["code"] == "BREACHED")
    assert breached["detail"] is not None
    assert "99" in breached["detail"]


def test_reason_details_are_localized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Le champ detail des raisons doit respecter la langue demandée."""
    async def no_breach(_password: str) -> GenericAppResult[int, AppError]:
        return GenericAppResult.success(0)

    monkeypatch.setattr(
        "app.services.password_analysis_service.check_password_breach", no_breach
    )
    # Mot de passe trop court → raison PASSWORD_TOO_SHORT
    response_fr = client.post(
        "/api/password/check", json={"password": "abc", "lang": "fr"}
    )
    response_en = client.post(
        "/api/password/check", json={"password": "abc", "lang": "en"}
    )

    detail_fr = response_fr.json()["result"]["reasons"][0]["detail"]
    detail_en = response_en.json()["result"]["reasons"][0]["detail"]

    assert detail_fr is not None
    assert detail_en is not None
    assert detail_fr != detail_en, "Les détails FR et EN doivent être différents"
