"""Provider-neutral interface for future language-model integrations.

Implementations must treat submitted content as untrusted input, use the
configured provider credentials, validate structured output, and return the
shared application result wrapper. This module intentionally makes no calls.
"""

from typing import Literal, Protocol

from app.common.app_result import GenericAppResult
from app.common.business_error import AppError
from app.schemas.analysis import AnalysisResult


class LLMClient(Protocol):
    async def analyze_email(
        self, content: str, lang: Literal["fr", "en"]
    ) -> GenericAppResult[AnalysisResult, AppError]:
        """Return a structured analysis result without persisting the content."""
