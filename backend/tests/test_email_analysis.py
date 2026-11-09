import asyncio

from app.common.app_result import GenericAppResult
from app.common.business_error import AppError
from app.common.utils.email_analysis import inspect_email
from app.schemas.analysis import Verdict
from app.schemas.email_analysis import EmailLLMAnalysis, EmailLLMReason
from app.schemas.analysis import Severity
from app.services.email_analysis_service import EmailAnalysisService


class FakeLLMClient:
    def __init__(self, response: EmailLLMAnalysis) -> None:
        self.response = response

    async def analyze_email(
        self, _content: str, _lang: str
    ) -> GenericAppResult[EmailLLMAnalysis, AppError]:
        return GenericAppResult.success(self.response)


def test_email_heuristics_detect_header_and_link_signals() -> None:
    content = """From: Support <security@paypal.com>
Reply-To: help@attacker.example
Authentication-Results: mx.example; spf=fail; dkim=pass; dmarc=fail
Content-Type: text/html

<a href="http://paypa1-login.xyz/signin">https://paypal.com</a>
URGENT: Verify your account and buy gift cards immediately.
"""

    analysis = inspect_email(content)
    codes = {signal.code for signal in analysis.signals}

    assert codes >= {
        "EMAIL_URGENCY",
        "EMAIL_CREDENTIAL_REQUEST",
        "EMAIL_GIFT_CARD_REQUEST",
        "EMAIL_LINK_MISMATCH",
        "EMAIL_REPLY_TO_MISMATCH",
        "EMAIL_AUTHENTICATION_FAILURE",
    }
    assert len(analysis.links) == 1


def test_email_heuristics_leave_normal_message_without_signals() -> None:
    analysis = inspect_email("Hello, the meeting is scheduled for Thursday.")

    assert analysis.signals == []
    assert analysis.links == []


def test_email_service_combines_local_and_model_analysis() -> None:
    client = FakeLLMClient(
        EmailLLMAnalysis(
            score=5,
            verdict=Verdict.SAFE,
            reasons=[
                EmailLLMReason(
                    code="EMAIL_SENSITIVE_DATA_REQUEST",
                    severity=Severity.HIGH,
                )
            ],
            tactics=[],
            explanation="No suspicious behavior detected.",
        )
    )
    service = EmailAnalysisService(client)

    result = asyncio.run(
        service.analyze(
            "URGENT: Verify your account at http://paypa1-login.xyz",
            "en",
        )
    )

    assert result.is_success()
    assert result.data.verdict == Verdict.DANGEROUS
    assert result.data.score >= 60
    assert {reason.code for reason in result.data.reasons} >= {
        "EMAIL_URGENCY",
        "EMAIL_CREDENTIAL_REQUEST",
        "TYPOSQUATTING",
        "EMAIL_BRAND_IMPERSONATION",
        "EMAIL_SENSITIVE_DATA_REQUEST",
    }
    assert "url_heuristics" in result.data.sources


def test_email_reason_details_are_localized() -> None:
    client = FakeLLMClient(
        EmailLLMAnalysis(
            score=0,
            verdict=Verdict.SAFE,
            reasons=[],
            tactics=[],
            explanation="OK",
        )
    )
    service = EmailAnalysisService(client)

    result_fr = asyncio.run(
        service.analyze("URGENT: action requise immédiatement", "fr")
    )
    result_en = asyncio.run(
        service.analyze("URGENT: action requise immédiatement", "en")
    )

    assert result_fr.is_success()
    assert result_en.is_success()

    urgency_fr = next(r for r in result_fr.data.reasons if r.code == "EMAIL_URGENCY")
    urgency_en = next(r for r in result_en.data.reasons if r.code == "EMAIL_URGENCY")

    assert urgency_fr.detail is not None
    assert urgency_en.detail is not None
    assert "alarmiste" in urgency_fr.detail
    assert "urgency" in urgency_en.detail
    assert urgency_fr.detail != urgency_en.detail


def test_email_service_returns_localized_reasons_from_llm() -> None:
    client = FakeLLMClient(
        EmailLLMAnalysis(
            score=75,
            verdict=Verdict.DANGEROUS,
            reasons=[
                EmailLLMReason(
                    code="EMAIL_UNSOLICITED_SOLICITATION",
                    severity=Severity.MEDIUM,
                ),
                EmailLLMReason(
                    code="EMAIL_FINANCIAL_INCENTIVE",
                    severity=Severity.MEDIUM,
                ),
                EmailLLMReason(
                    code="EMAIL_SENSITIVE_DATA_REQUEST",
                    severity=Severity.HIGH,
                ),
            ],
            tactics=["Sollicitation non sollicitée", "Appât financier"],
            explanation="Une offre réclame des données propriétaires.",
        )
    )
    service = EmailAnalysisService(client)
    sample_email = (
        "A vendor offers compensation for sharing private production source code."
    )

    result = asyncio.run(service.analyze(sample_email, "fr"))

    assert result.is_success()
    reasons = {reason.code: reason for reason in result.data.reasons}
    assert {
        "EMAIL_UNSOLICITED_SOLICITATION",
        "EMAIL_FINANCIAL_INCENTIVE",
        "EMAIL_SENSITIVE_DATA_REQUEST",
    } <= reasons.keys()
    assert all(
        reasons[code].detail
        for code in (
            "EMAIL_UNSOLICITED_SOLICITATION",
            "EMAIL_FINANCIAL_INCENTIVE",
            "EMAIL_SENSITIVE_DATA_REQUEST",
        )
    )
