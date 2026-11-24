from fastapi import status

from app.common.app_result import GenericAppResult
from app.common.business_error import AppError
from app.integrations.url_reputation import (
    ReputationResult,
    check_url_reputation,
)
from app.repositories import CrudResult


class UrlReputationRepository:
    async def inspect(self, url: str) -> CrudResult[ReputationResult, AppError]:
        result: GenericAppResult[ReputationResult, AppError]
        result = await check_url_reputation(url)
        if result.is_error():
            return CrudResult.crud_failure(
                error=result.error,
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        return CrudResult.crud_success(result.data)
