import asyncio
import hashlib
from dataclasses import dataclass
from typing import Literal

import httpx
from cachetools import TTLCache

from app.common.app_result import GenericAppResult
from app.common.business_error import AppError, AppErrorType
from app.core.config import settings
from app.integrations.domain_metadata import extract_hostname

_URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"
_GOOGLE_SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)
_VIRUSTOTAL_URLS_URL = "https://www.virustotal.com/api/v3/urls"


@dataclass(frozen=True)
class ReputationMatch:
    source: Literal[
        "google_safe_browsing",
        "urlhaus",
        "virustotal",
    ]
    code: Literal[
        "GOOGLE_SAFE_BROWSING_MATCH",
        "URLHAUS_MATCH",
        "VIRUSTOTAL_MALICIOUS",
        "VIRUSTOTAL_SUSPICIOUS",
    ]
    severity: Literal["low", "medium", "high"]
    points: int


@dataclass(frozen=True)
class ReputationResult:
    matches: tuple[ReputationMatch, ...]


_reputation_cache: TTLCache[str, ReputationResult] = TTLCache(
    maxsize=settings.URL_REPUTATION_CACHE_MAXSIZE,
    ttl=settings.URL_REPUTATION_CACHE_TTL,
)
_reputation_locks: dict[str, asyncio.Lock] = {}
_reputation_semaphore: asyncio.Semaphore | None = None


def _cache_key(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def _unavailable_error() -> AppError:
    return AppError(
        error_type=AppErrorType.UNKNOWN_ERROR,
        error_message="URL reputation unavailable",
    )


def _get_semaphore() -> asyncio.Semaphore:
    global _reputation_semaphore
    if _reputation_semaphore is None:
        _reputation_semaphore = asyncio.Semaphore(
            settings.URL_REPUTATION_MAX_CONCURRENT
        )
    return _reputation_semaphore


async def _check_urlhaus(hostname: str) -> ReputationResult:
    if not settings.URLHAUS_ENABLED:
        return ReputationResult(matches=())

    try:
        async with httpx.AsyncClient(
            timeout=settings.URL_REPUTATION_TIMEOUT,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.post(
                _URLHAUS_HOST_URL,
                data={"host": hostname},
            )
            if response.status_code == 200:
                payload = response.json()
                if (
                    isinstance(payload, dict)
                    and payload.get("query_status") == "ok"
                    and payload.get("urls")
                ):
                    return ReputationResult(
                        matches=(
                            ReputationMatch(
                                source="urlhaus",
                                code="URLHAUS_MATCH",
                                severity="high",
                                points=55,
                            ),
                        )
                    )
    except (httpx.HTTPError, ValueError):
        pass
    return ReputationResult(matches=())


async def _check_google_safe_browsing(url: str) -> ReputationResult:
    api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY.strip()
    if not api_key:
        return ReputationResult(matches=())

    try:
        async with httpx.AsyncClient(
            timeout=settings.URL_REPUTATION_TIMEOUT,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.post(
                f"{_GOOGLE_SAFE_BROWSING_URL}?key={api_key}",
                json={
                    "client": {
                        "clientId": "flair",
                        "clientVersion": "1",
                    },
                    "threatInfo": {
                        "threatTypes": [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION",
                        ],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}],
                    },
                },
            )
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError):
        return ReputationResult(matches=())

    if isinstance(payload, dict) and payload.get("matches"):
        return ReputationResult(
            matches=(
                ReputationMatch(
                    source="google_safe_browsing",
                    code="GOOGLE_SAFE_BROWSING_MATCH",
                    severity="high",
                    points=60,
                ),
            )
        )
    return ReputationResult(matches=())


async def _check_virustotal(url: str) -> ReputationResult:
    api_key = settings.VIRUSTOTAL_API_KEY.strip()
    if not api_key:
        return ReputationResult(matches=())

    headers = {"x-apikey": api_key}
    try:
        async with httpx.AsyncClient(
            timeout=settings.URL_REPUTATION_TIMEOUT,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            submit = await client.post(
                _VIRUSTOTAL_URLS_URL,
                headers=headers,
                data={"url": url},
            )
            if submit.status_code not in {200, 202}:
                return ReputationResult(matches=())
            submit_payload = submit.json()
            analysis_id = (
                submit_payload.get("data", {}).get("id")
                if isinstance(submit_payload, dict)
                else None
            )
            if not isinstance(analysis_id, str):
                return ReputationResult(matches=())

            report = await client.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
            )
            if report.status_code != 200:
                return ReputationResult(matches=())
            report_payload = report.json()
    except (httpx.HTTPError, ValueError):
        return ReputationResult(matches=())

    stats = (
        report_payload.get("data", {})
        .get("attributes", {})
        .get("stats", {})
    )
    if not isinstance(stats, dict):
        return ReputationResult(matches=())

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if isinstance(malicious, int) and malicious > 0:
        return ReputationResult(
            matches=(
                ReputationMatch(
                    source="virustotal",
                    code="VIRUSTOTAL_MALICIOUS",
                    severity="high",
                    points=50,
                ),
            )
        )
    if isinstance(suspicious, int) and suspicious > 0:
        return ReputationResult(
            matches=(
                ReputationMatch(
                    source="virustotal",
                    code="VIRUSTOTAL_SUSPICIOUS",
                    severity="medium",
                    points=30,
                ),
            )
        )
    return ReputationResult(matches=())


async def check_url_reputation(
    url: str,
) -> GenericAppResult[ReputationResult, AppError]:
    hostname = extract_hostname(url)
    if hostname is None:
        return GenericAppResult.failure(_unavailable_error())

    if not settings.URL_REPUTATION_ENABLED:
        return GenericAppResult.success(ReputationResult(matches=()))

    key = _cache_key(url)
    cached = _reputation_cache.get(key)
    if cached is not None:
        return GenericAppResult.success(cached)

    lock = _reputation_locks.setdefault(key, asyncio.Lock())
    async with lock:
        cached = _reputation_cache.get(key)
        if cached is not None:
            return GenericAppResult.success(cached)

        async with _get_semaphore():
            checks = [
                _check_urlhaus(hostname),
                _check_google_safe_browsing(url),
                _check_virustotal(url),
            ]
            results = await asyncio.gather(*checks)

    matches = tuple(
        match
        for result in results
        for match in result.matches
    )
    reputation = ReputationResult(matches=matches)
    _reputation_cache[key] = reputation
    _reputation_locks.pop(key, None)
    return GenericAppResult.success(reputation)
