from pydantic import BaseModel, Field

from app.common.business_error import AppError
from app.schemas.shared.api_base_response import ApiBaseResponse


class StringMessage(BaseModel):
    message: str = Field(description="Message describing the successful operation.")


class GlobalStringResponse(ApiBaseResponse[StringMessage, AppError]):
    pass
