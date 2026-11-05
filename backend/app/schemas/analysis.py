from enum import Enum

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Reason(BaseModel):
    code: str
    severity: Severity
    detail: str | None = None


class AnalysisResult(BaseModel):
    score: int = Field(ge=0, le=100)
    verdict: Verdict
    reasons: list[Reason]
    sources: list[str]
    tactics: list[str] | None = None
    explanation: str | None = None
    breach_count: int | None = None
