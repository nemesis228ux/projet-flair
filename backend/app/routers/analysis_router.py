from fastapi import APIRouter, Response

from app.common.business_error import AppError
from app.schemas.analysis import AnalysisResult
from app.schemas.analysis_requests import (
    EmailAnalyzeRequest,
    PasswordCheckRequest,
    UrlAnalyzeRequest,
)
from app.schemas.shared.api_base_response import ApiBaseResponse
from app.services import ServiceResult
from app.services.analysis_service import analyze_email, analyze_url, check_password

router = APIRouter(tags=["analysis"])


@router.post("/url/analyze", response_model=ApiBaseResponse[AnalysisResult, AppError])
async def post_url_analysis(
    _request: UrlAnalyzeRequest, response: Response
) -> ApiBaseResponse[AnalysisResult, AppError]:
    result: ServiceResult[AnalysisResult, AppError] = analyze_url()
    return result.to_HTTP_api_base_response(response)


@router.post(
    "/email/analyze", response_model=ApiBaseResponse[AnalysisResult, AppError]
)
async def post_email_analysis(
    _request: EmailAnalyzeRequest, response: Response
) -> ApiBaseResponse[AnalysisResult, AppError]:
    result: ServiceResult[AnalysisResult, AppError] = analyze_email()
    return result.to_HTTP_api_base_response(response)


@router.post(
    "/password/check", response_model=ApiBaseResponse[AnalysisResult, AppError]
)
async def post_password_check(
    _request: PasswordCheckRequest, response: Response
) -> ApiBaseResponse[AnalysisResult, AppError]:
    result: ServiceResult[AnalysisResult, AppError] = check_password()
    return result.to_HTTP_api_base_response(response)
