from fastapi import APIRouter, Response
from pydantic import BaseModel

from app.common.business_error import AppError
from app.schemas.shared.api_base_response import ApiBaseResponse
from app.services import ServiceResult


class HealthResponse(BaseModel):
    status: str


router = APIRouter(tags=["health"])


@router.get("/api/v1/health", response_model=ApiBaseResponse[HealthResponse, AppError])
async def health(response: Response) -> ApiBaseResponse[HealthResponse, AppError]:
    result: ServiceResult[HealthResponse, AppError] = ServiceResult.service_success(
        data=HealthResponse(status="ok")
    )
    return result.to_HTTP_api_base_response(response)
