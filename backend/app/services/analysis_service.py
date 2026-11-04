from app.common.business_error import AppError
from app.schemas.analysis import AnalysisResult, Reason, Severity, Verdict
from app.services import ServiceResult


def _mock_result() -> AnalysisResult:
    return AnalysisResult(
        score=50,
        verdict=Verdict.SUSPICIOUS,
        reasons=[Reason(code="STUB_RESULT", severity=Severity.LOW)],
        sources=["stub"],
    )


def analyze_url() -> ServiceResult[AnalysisResult, AppError]:
    return ServiceResult.service_success(data=_mock_result())


def analyze_email() -> ServiceResult[AnalysisResult, AppError]:
    return ServiceResult.service_success(data=_mock_result())


def check_password() -> ServiceResult[AnalysisResult, AppError]:
    return ServiceResult.service_success(data=_mock_result())
