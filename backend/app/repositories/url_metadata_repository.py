from fastapi import status

from app.common.app_result import GenericAppResult
from app.common.business_error import AppError
from app.integrations.domain_metadata import (
    DomainMetadata,
    query_domain_metadata,
)
from app.repositories import CrudResult


class UrlMetadataRepository:
    async def inspect(self, url: str) -> CrudResult[DomainMetadata, AppError]:
        result: GenericAppResult[DomainMetadata, AppError]
        result = await query_domain_metadata(url)
        if result.is_error():
            return CrudResult.crud_failure(
                error=result.error,
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        return CrudResult.crud_success(result.data)
