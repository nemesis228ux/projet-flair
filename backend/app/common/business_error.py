from enum import Enum

from pydantic import BaseModel, Field


class AppErrorType(str, Enum):
    NOT_FOUND = "NOT_FOUND"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"
    BAD_REQUEST = "BAD_REQUEST"
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    VALIDATION_ERROR = "VALIDATION_ERROR"


class AppError(BaseModel):
    error_type: AppErrorType = Field(description="Category of the application error.")
    error_message: str = Field(description="User-facing description of the error.")

    def __str__(self) -> str:
        return f"AppError(type={self.error_type}, message={self.error_message})"
