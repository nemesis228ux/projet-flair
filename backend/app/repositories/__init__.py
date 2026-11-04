from typing import Generic, TypeVar

from fastapi import status

from app.common.app_result import GenericAppResult, _MISSING
from app.common.business_error import AppError
from app.services import ServiceResult

D = TypeVar("D")
E = TypeVar("E")


class CrudResult(GenericAppResult[D, E], Generic[D, E]):
    def __init__(
        self,
        ok: bool,
        status_code: int,
        data: D | object = _MISSING,
        error: E | object = _MISSING,
    ) -> None:
        super().__init__(ok=ok, data=data, error=error)
        self._status_code = status_code

    @property
    def status_code(self) -> int:
        return self._status_code

    @classmethod
    def crud_success(
        cls, data: D, status_code: int = status.HTTP_200_OK
    ) -> "CrudResult[D, E]":
        return cls(ok=True, data=data, status_code=status_code)

    @classmethod
    def crud_failure(
        cls, error: E, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    ) -> "CrudResult[D, E]":
        return cls(ok=False, error=error, status_code=status_code)

    def to_service_error(
        self, service_name: str
    ) -> "ServiceResult[D, E]":
        return ServiceResult.service_failure(
            error=self.error,
            status_code=self.status_code,
            service_name=service_name,
        )


DefaultAppCrudResult = CrudResult[D, AppError]

__all__ = ["CrudResult", "DefaultAppCrudResult"]