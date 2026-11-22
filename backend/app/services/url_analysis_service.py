from datetime import datetime, timezone

from app.common.business_error import AppError
from app.common.utils.url_analysis import (
    UrlRiskSignal,
    _signal,
    inspect_url,
)
from app.common.utils.url_analysis_i18n import get_signal_detail
from app.core.config import settings
from app.integrations.domain_metadata import DomainMetadata
from app.repositories.url_metadata_repository import UrlMetadataRepository
from app.schemas.analysis import AnalysisResult, Reason, Severity, Verdict
from app.services import ServiceResult


class UrlAnalysisService:
    service_name = "URL_ANALYSIS_SERVICE"

    def __init__(
        self,
        metadata_repository: UrlMetadataRepository | None = None,
    ) -> None:
        self.metadata_repository = (
            metadata_repository or UrlMetadataRepository()
        )

    @staticmethod
    def _metadata_signals(
        metadata: DomainMetadata,
    ) -> list[UrlRiskSignal]:
        signals: list[UrlRiskSignal] = []
        now = datetime.now(timezone.utc)

        if metadata.registration_date is not None:
            registered = metadata.registration_date
            if registered.tzinfo is None:
                registered = registered.replace(tzinfo=timezone.utc)
            age_days = max(
                0,
                (now - registered.astimezone(timezone.utc)).days,
            )
            if age_days <= 7:
                signals.append(
                    _signal("DOMAIN_TOO_NEW", Severity.HIGH, 35, str(age_days))
                )
            elif age_days <= 30:
                signals.append(
                    _signal("DOMAIN_TOO_NEW", Severity.MEDIUM, 25, str(age_days))
                )
            elif age_days <= 365:
                signals.append(
                    _signal("DOMAIN_RECENT", Severity.LOW, 10, str(age_days))
                )

        if metadata.dns_status == "confirmed_negative":
            signals.append(
                _signal("DNS_UNRESOLVED", Severity.HIGH, 30)
            )

        return signals

    async def analyze(
        self, url: str, lang: str = "fr"
    ) -> ServiceResult[AnalysisResult, AppError]:
        signals = inspect_url(url)
        sources = ["heuristics"]

        if settings.URL_METADATA_ENABLED:
            metadata_result = await self.metadata_repository.inspect(url)
            if metadata_result.is_success():
                metadata = metadata_result.data
                signals.extend(self._metadata_signals(metadata))
                if metadata.rdap_available:
                    sources.append("rdap")
                if metadata.dns_status in {
                    "available",
                    "confirmed_negative",
                }:
                    sources.append("dns")

        score = min(sum(signal.points for signal in signals), 100)

        if score >= 60:
            verdict = Verdict.DANGEROUS
        elif score >= 20:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.SAFE

        result = AnalysisResult(
            score=score,
            verdict=verdict,
            reasons=[
                Reason(
                    code=signal.code,
                    severity=signal.severity,
                    detail=get_signal_detail(signal.code, lang, signal.detail),
                )
                for signal in signals
            ],
            sources=sources,
        )
        return ServiceResult.service_success(
            data=result,
            service_name=self.service_name,
        )
