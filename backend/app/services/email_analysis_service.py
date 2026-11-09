from collections.abc import Iterable
from typing import Literal

from app.common.business_error import AppError
from app.common.constants.services_names import ServicesNames
from app.common.utils.email_analysis import inspect_email
from app.common.utils.email_analysis_i18n import get_email_signal_detail
from app.common.utils.url_analysis import inspect_url
from app.common.utils.url_analysis_i18n import get_signal_detail as get_url_signal_detail
from app.integrations.llm import LLMClient, get_llm_client
from app.schemas.analysis import AnalysisResult, Reason, Severity, Verdict
from app.services import ServiceResult


class EmailAnalysisService:
    service_name = ServicesNames.EMAIL_ANALYSIS_SERVICE

    def __init__(self, llm_client: LLMClient | None = None) -> None:
        self._llm_client = llm_client or get_llm_client()

    async def analyze(
        self, content: str, lang: Literal["fr", "en"]
    ) -> ServiceResult[AnalysisResult, AppError]:
        heuristic_result = inspect_email(content)
        reasons = [
            Reason(
                code=signal.code,
                severity=signal.severity,
                detail=get_email_signal_detail(signal.code, lang),
            )
            for signal in heuristic_result.signals
        ]
        local_score = sum(signal.points for signal in heuristic_result.signals)
        sources = ["heuristics"]

        if heuristic_result.links:
            sources.append("url_heuristics")
        for link in heuristic_result.links:
            url_signals = inspect_url(link.url)
            local_score += sum(signal.points for signal in url_signals)
            reasons.extend(
                Reason(
                    code=signal.code,
                    severity=signal.severity,
                    detail=get_url_signal_detail(signal.code, lang, signal.detail),
                )
                for signal in url_signals
            )
            if any(signal.code == "TYPOSQUATTING" for signal in url_signals):
                reasons.append(
                    Reason(
                        code="EMAIL_BRAND_IMPERSONATION",
                        severity=Severity.HIGH,
                        detail=get_email_signal_detail("EMAIL_BRAND_IMPERSONATION", lang),
                    )
                )

        llm_result = await self._llm_client.analyze_email(content, lang)
        if llm_result.is_error():
            return ServiceResult.service_failure(
                error=llm_result.error,
                status_code=503,
                service_name=self.service_name,
            )

        llm_analysis = llm_result.data
        reasons.extend(
            Reason(
                code=reason.code,
                severity=reason.severity,
                detail=get_email_signal_detail(reason.code, lang),
            )
            for reason in llm_analysis.reasons
        )
        llm_score = max(
            llm_analysis.score,
            60 if llm_analysis.verdict == Verdict.DANGEROUS else 0,
            20 if llm_analysis.verdict == Verdict.SUSPICIOUS else 0,
        )
        score = min(max(local_score, llm_score), 100)
        if score >= 60:
            verdict = Verdict.DANGEROUS
        elif score >= 20:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.SAFE

        result = AnalysisResult(
            score=score,
            verdict=verdict,
            reasons=_unique_reasons(reasons),
            sources=[*sources, "llm"],
            tactics=llm_analysis.tactics,
            explanation=llm_analysis.explanation,
        )
        return ServiceResult.service_success(
            data=result,
            service_name=self.service_name,
        )


def _unique_reasons(reasons: Iterable[Reason]) -> list[Reason]:
    unique: dict[str, Reason] = {}
    for reason in reasons:
        current = unique.get(reason.code)
        if current is None or _severity_rank(reason.severity) > _severity_rank(
            current.severity
        ):
            unique[reason.code] = reason
    return list(unique.values())


def _severity_rank(severity: Severity) -> int:
    return {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
    }[severity]
