from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.analysis import Severity, Verdict

EmailReasonCode = Literal[
    "EMAIL_UNSOLICITED_SOLICITATION",
    "EMAIL_FINANCIAL_INCENTIVE",
    "EMAIL_SENSITIVE_DATA_REQUEST",
    "EMAIL_BRAND_IMPERSONATION",
    "EMAIL_URGENCY",
    "EMAIL_CREDENTIAL_REQUEST",
    "EMAIL_MONEY_REQUEST",
    "EMAIL_GIFT_CARD_REQUEST",
    "EMAIL_LINK_MISMATCH",
    "EMAIL_REPLY_TO_MISMATCH",
    "EMAIL_AUTHENTICATION_FAILURE",
]


class EmailLLMReason(BaseModel):
    code: EmailReasonCode
    severity: Severity


class EmailLLMAnalysis(BaseModel):
    score: int = Field(ge=0, le=100)
    verdict: Verdict
    reasons: list[EmailLLMReason] = Field(max_length=8)
    tactics: list[str] = Field(max_length=8)
    explanation: str = Field(min_length=1, max_length=2000)
