from app.common.business_error import AppError
from app.common.constants.services_names import ServicesNames
from app.common.utils.password_analysis_i18n import get_password_signal_detail
from app.integrations.hibp import check_password_breach
from app.schemas.analysis import AnalysisResult, Reason, Severity, Verdict
from app.services import ServiceResult
from zxcvbn import zxcvbn

# Mapping zxcvbn score (0–4) → score de risque (0–100).
# zxcvbn:
#   0 = trop devinable  (< 10³ tentatives)   → risque maximal
#   1 = très devinable  (< 10⁶)              → risque élevé
#   2 = assez devinable (< 10⁸)              → risque modéré
#   3 = sûr             (< 10¹⁰)             → risque faible  (SAFE)
#   4 = très sûr        (≥ 10¹⁰)             → risque nul     (SAFE)
# Avec les seuils de verdict : ≥60 → DANGEROUS, ≥20 → SUSPICIOUS, <20 → SAFE
_ZXCVBN_RISK_SCORE: dict[int, int] = {0: 100, 1: 75, 2: 45, 3: 10, 4: 0}


class PasswordAnalysisService:
    service_name = ServicesNames.PASSWORD_ANALYSIS_SERVICE

    async def analyze(
        self, password: str, lang: str = "fr"
    ) -> ServiceResult[AnalysisResult, AppError]:
        strength = zxcvbn(password)
        strength_score = strength.get("score")
        if not isinstance(strength_score, int) or not 0 <= strength_score <= 4:
            raise RuntimeError(
                "The password strength estimator returned an invalid score."
            )

        breach_result = await check_password_breach(password)
        if breach_result.is_error():
            return ServiceResult.service_failure(
                error=breach_result.error,
                status_code=503,
                service_name=self.service_name,
            )

        breach_count = breach_result.data
        score = 100 if breach_count > 0 else _ZXCVBN_RISK_SCORE[strength_score]
        reasons: list[Reason] = []

        if len(password) < 8:
            reasons.append(
                Reason(
                    code="PASSWORD_TOO_SHORT",
                    severity=Severity.HIGH,
                    detail=get_password_signal_detail("PASSWORD_TOO_SHORT", lang),
                )
            )
        elif strength_score <= 1:
            reasons.append(
                Reason(
                    code="PASSWORD_WEAK",
                    severity=Severity.HIGH,
                    detail=get_password_signal_detail("PASSWORD_WEAK", lang),
                )
            )
        elif strength_score == 2:
            reasons.append(
                Reason(
                    code="PASSWORD_WEAK",
                    severity=Severity.MEDIUM,
                    detail=get_password_signal_detail("PASSWORD_WEAK", lang),
                )
            )

        if breach_count > 0:
            reasons.append(
                Reason(
                    code="BREACHED",
                    severity=Severity.HIGH,
                    detail=get_password_signal_detail(
                        "BREACHED", lang, detail=str(breach_count)
                    ),
                )
            )

        if score >= 60:
            verdict = Verdict.DANGEROUS
        elif score >= 20:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.SAFE

        result = AnalysisResult(
            score=score,
            verdict=verdict,
            reasons=reasons,
            sources=["zxcvbn", "hibp"],
            breach_count=breach_count,
        )
        return ServiceResult.service_success(
            data=result,
            service_name=self.service_name,
        )
