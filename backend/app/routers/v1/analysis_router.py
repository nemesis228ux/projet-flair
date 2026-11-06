from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from app.common.business_error import AppError
from app.core.rate_limit import limiter
from app.schemas.analysis import AnalysisResult
from app.schemas.analysis_requests import (
    EmailAnalyzeRequest,
    PasswordCheckRequest,
    UrlAnalyzeRequest,
)
from app.schemas.shared.api_base_response import ApiBaseResponse
from app.services import ServiceResult
from app.services.email_analysis_service import analyze_email
from app.services.password_analysis_service import PasswordAnalysisService
from app.services.url_analysis_service import UrlAnalysisService

router = APIRouter(tags=["analysis"])


def get_url_analysis_service() -> UrlAnalysisService:
    return UrlAnalysisService()


def get_password_analysis_service() -> PasswordAnalysisService:
    return PasswordAnalysisService()


@router.post("/url/analyze", response_model=ApiBaseResponse[AnalysisResult, AppError])
@limiter.limit("5/minute")
async def post_url_analysis(
    request: UrlAnalyzeRequest,
    response: Response,
    service: Annotated[UrlAnalysisService, Depends(get_url_analysis_service)],
) -> ApiBaseResponse[AnalysisResult, AppError]:
    result: ServiceResult[AnalysisResult, AppError] = service.analyze(
        request.url, lang=request.lang
    )
    return result.to_HTTP_api_base_response(response)


@router.post(
    "/email/analyze", response_model=ApiBaseResponse[AnalysisResult, AppError]
)
@limiter.limit("5/minute")
async def post_email_analysis(
    _request: EmailAnalyzeRequest, response: Response
) -> ApiBaseResponse[AnalysisResult, AppError]:
    result: ServiceResult[AnalysisResult, AppError] = analyze_email()
    return result.to_HTTP_api_base_response(response)



@router.post(
    "/password/check", response_model=ApiBaseResponse[AnalysisResult, AppError]
)
@limiter.limit("5/minute")
async def post_password_check(
    payload: PasswordCheckRequest,
    response: Response,
    service: Annotated[
        PasswordAnalysisService, Depends(get_password_analysis_service)
    ],
) -> ApiBaseResponse[AnalysisResult, AppError]:
    result: ServiceResult[AnalysisResult, AppError] = await service.analyze(
        payload.password, lang=payload.lang
    )
    return result.to_HTTP_api_base_response(response)
