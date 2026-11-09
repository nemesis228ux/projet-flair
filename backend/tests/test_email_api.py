from collections.abc import Iterator

from fastapi.testclient import TestClient
import pytest

from app.common.app_result import GenericAppResult
from app.common.business_error import AppError, AppErrorType
from app.core.rate_limit import limiter
from app.main import app
from app.routers.v1.analysis_router import get_email_analysis_service
from app.schemas.analysis import Verdict
from app.schemas.email_analysis import EmailLLMAnalysis
from app.services.email_analysis_service import EmailAnalysisService

client = TestClient(app)


class FakeLLMClient:
    def __init__(
        self,
        result: GenericAppResult[EmailLLMAnalysis, AppError] | None = None,
    ) -> None:
        self.result = result or GenericAppResult.success(
            EmailLLMAnalysis(
                score=10,
                verdict=Verdict.SAFE,
                reasons=[],
                tactics=[],
                explanation="Aucune tactique suspecte détectée.",
            )
        )

    async def analyze_email(
        self, _content: str, _lang: str
    ) -> GenericAppResult[EmailLLMAnalysis, AppError]:
        return self.result


@pytest.fixture(autouse=True)
def clear_rate_limit_and_dependency_override() -> Iterator[None]:
    limiter.reset()
    app.dependency_overrides.pop(get_email_analysis_service, None)
    yield
    app.dependency_overrides.pop(get_email_analysis_service, None)


def test_email_analysis_returns_combined_wrapper() -> None:
    app.dependency_overrides[get_email_analysis_service] = lambda: (
        EmailAnalysisService(FakeLLMClient())
    )
    response = client.post(
        "/api/v1/email/analyze",
        json={
            "content": "URGENT: Verify your account password immediately.",
            "lang": "fr",
        },
    )

    assert response.status_code == 200
    assert response.json()["success"] is True
    result = response.json()["result"]
    assert result["verdict"] == "suspicious"
    assert result["score"] >= 20
    assert result["sources"] == ["heuristics", "llm"]
    assert "EMAIL_CREDENTIAL_REQUEST" in {
        reason["code"] for reason in result["reasons"]
    }
    assert result["explanation"] == "Aucune tactique suspecte détectée."
    assert result["reasons"]


def test_email_analysis_returns_generic_error_when_gemini_unavailable() -> None:
    failure = GenericAppResult.failure(
        AppError(
            error_type=AppErrorType.UNKNOWN_ERROR,
            error_message="Unavailable",
        )
    )
    app.dependency_overrides[get_email_analysis_service] = lambda: (
        EmailAnalysisService(FakeLLMClient(failure))
    )

    response = client.post(
        "/api/v1/email/analyze",
        json={"content": "Private message content", "lang": "en"},
    )

    assert response.status_code == 503
    assert response.json()["success"] is False
    assert "Private message content" not in response.text


def test_email_analysis_limits_content_without_echoing_it() -> None:
    content = "private-email-" + "x" * 50000
    response = client.post(
        "/api/v1/email/analyze",
        json={"content": content, "lang": "en"},
    )

    assert response.status_code == 422
    assert response.json()["success"] is False
    assert content not in response.text
