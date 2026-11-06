from app.common.business_error import AppError
from app.schemas.analysis import AnalysisResult, Reason, Severity, Verdict
from app.services import ServiceResult


def analyze_email() -> ServiceResult[AnalysisResult, AppError]:
    result = AnalysisResult(
        score=50,
        verdict=Verdict.SUSPICIOUS,
        reasons=[Reason(code="STUB_RESULT", severity=Severity.LOW)],
        sources=["stub"],
    )
    return ServiceResult.service_success(data=result)
