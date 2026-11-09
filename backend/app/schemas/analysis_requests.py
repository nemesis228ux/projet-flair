from typing import Literal

from pydantic import BaseModel, Field


class UrlAnalyzeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    lang: Literal["fr", "en"]


class EmailAnalyzeRequest(BaseModel):
    content: str = Field(min_length=1, max_length=50000)
    lang: Literal["fr", "en"]


class PasswordCheckRequest(BaseModel):
    password: str = Field(min_length=1, max_length=128)
    lang: Literal["fr", "en"]
