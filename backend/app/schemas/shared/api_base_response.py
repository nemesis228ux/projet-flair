from typing import Generic, TypeVar

from fastapi import Response
from pydantic import BaseModel, Field, model_validator

from app.common.business_error import AppError

D = TypeVar("D")
E = TypeVar("E")


class ApiBaseResponse(BaseModel, Generic[D, E]):
    success: bool = Field(description="Whether the request succeeded.")
    result: D | None = Field(default=None, description="Successful response data.")
    error: E | None = Field(default=None, description="Error details on failure.")

    @model_validator(mode="after")
    def check_response(self) -> "ApiBaseResponse[D, E]":
        if self.success and self.error is not None:
            raise ValueError("The error field must be null on success.")
        if not self.success and self.result is not None:
            raise ValueError("The result field must be null on failure.")
        return self

    @classmethod
    def success_response(
        cls,
        data: D,
        response: Response,
        status_code: int = 200,
    ) -> "ApiBaseResponse[D, E]":
        response.status_code = status_code
        return cls(success=True, result=data, error=None)

    @classmethod
    def error_response(
        cls,
        error_message: E,
        response: Response,
        status_code: int = 400,
    ) -> "ApiBaseResponse[D, E]":
        response.status_code = status_code
        return cls(success=False, result=None, error=error_message)


DefaultAppApiResponse = ApiBaseResponse[D, AppError]
