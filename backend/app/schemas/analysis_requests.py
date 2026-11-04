from typing import Literal

from pydantic import BaseModel, Field


class UrlAnalyzeRequest(BaseModel):
    url: str
    lang: Literal["fr", "en"]


class EmailAnalyzeRequest(BaseModel):
    content: str
    lang: Literal["fr", "en"]


class PasswordCheckRequest(BaseModel):
    password: str = Field(max_length=128)
    lang: Literal["fr", "en"]
