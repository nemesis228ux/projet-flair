from app.common.business_error import AppError
from app.common.utils.url_analysis import inspect_url
from app.common.utils.url_analysis_i18n import get_signal_detail
from app.schemas.analysis import AnalysisResult, Reason, Severity, Verdict
from app.services import ServiceResult


def _mock_result() -> AnalysisResult:
    return AnalysisResult(
        score=50,
        verdict=Verdict.SUSPICIOUS,
        reasons=[Reason(code="STUB_RESULT", severity=Severity.LOW)],
        sources=["stub"],
    )


class UrlAnalysisService:
    service_name = "URL_ANALYSIS_SERVICE"

    def analyze(self, url: str, lang: str = "fr") -> ServiceResult[AnalysisResult, AppError]:
        signals = inspect_url(url)
        score = min(sum(signal.points for signal in signals), 100)

        if score >= 60:
            verdict = Verdict.DANGEROUS
        elif score >= 20:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.SAFE

        result = AnalysisResult(
            score=score,
            verdict=verdict,
            reasons=[
                Reason(
                    code=signal.code,
                    severity=signal.severity,
                    detail=get_signal_detail(signal.code, lang, signal.detail),
                )
                for signal in signals
            ],
            sources=["heuristics"],
        )
        return ServiceResult.service_success(
            data=result,
            service_name=self.service_name,
        )


def analyze_email() -> ServiceResult[AnalysisResult, AppError]:
    return ServiceResult.service_success(data=_mock_result())


def check_password() -> ServiceResult[AnalysisResult, AppError]:
    return ServiceResult.service_success(data=_mock_result())
