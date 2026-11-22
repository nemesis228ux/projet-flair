import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import quote, urlsplit

import httpx
from cachetools import TTLCache

try:
    from publicsuffix2 import get_sld
except ImportError:
    get_sld = None

from app.common.app_result import GenericAppResult
from app.common.business_error import AppError, AppErrorType
from app.core.config import settings

_RDAP_BOOTSTRAP_URL = "https://rdap-bootstrap.iana.org/domain/"
DnsStatus = Literal["available", "confirmed_negative", "unavailable"]


@dataclass(frozen=True)
class DomainMetadata:
    domain: str
    rdap_available: bool = False
    dns_status: DnsStatus = "unavailable"
    registration_date: datetime | None = None


_metadata_cache: TTLCache[str, DomainMetadata] = TTLCache(
    maxsize=settings.URL_METADATA_CACHE_MAXSIZE,
    ttl=settings.URL_METADATA_CACHE_TTL,
)
_refresh_locks: dict[str, asyncio.Lock] = {}
_refresh_semaphore: asyncio.Semaphore | None = None


def extract_hostname(value: str) -> str | None:
    try:
        parsed = urlsplit(value if "://" in value else f"//{value}")
        hostname = parsed.hostname
    except ValueError:
        return None
    if not hostname:
        return None

    hostname = hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass

    if hostname == "localhost" or hostname.endswith(".localhost"):
        return None
    return hostname if "." in hostname else None


def registered_domain(hostname: str) -> str | None:
    host = hostname.rstrip(".").lower()
    if get_sld is not None:
        try:
            domain = get_sld(host)
        except (AttributeError, ValueError):
            domain = None
        if isinstance(domain, str) and "." in domain:
            return domain

    labels = host.split(".")
    if len(labels) < 2:
        return None
    return ".".join(labels[-2:])


def _parse_registration_date(payload: object) -> datetime | None:
    if not isinstance(payload, dict):
        return None
    events = payload.get("events")
    if not isinstance(events, list):
        return None
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("eventAction") not in {"registration", "registered"}:
            continue
        value = event.get("eventDate")
        if not isinstance(value, str):
            continue
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


async def _query_rdap(domain: str) -> tuple[bool, datetime | None]:
    try:
        async with httpx.AsyncClient(
            timeout=settings.URL_METADATA_TIMEOUT,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.get(
                f"{_RDAP_BOOTSTRAP_URL}{quote(domain, safe='.')}"
            )
            if response.status_code != 200:
                return False, None
            payload = response.json()
    except (httpx.HTTPError, ValueError):
        return False, None
    return True, _parse_registration_date(payload)


async def _query_dns(domain: str) -> DnsStatus:
    loop = asyncio.get_running_loop()
    try:
        records = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(
                    domain,
                    443,
                    type=socket.SOCK_STREAM,
                ),
            ),
            timeout=settings.URL_METADATA_TIMEOUT,
        )
    except socket.gaierror as exception:
        if getattr(exception, "errno", None) in {
            socket.EAI_NONAME,
            socket.EAI_NODATA,
        }:
            return "confirmed_negative"
        return "unavailable"
    except asyncio.TimeoutError:
        return "unavailable"
    except OSError:
        return "unavailable"

    for record in records:
        address = record[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return "available"
    return "confirmed_negative"


def _get_refresh_semaphore() -> asyncio.Semaphore:
    global _refresh_semaphore
    if _refresh_semaphore is None:
        _refresh_semaphore = asyncio.Semaphore(
            settings.URL_METADATA_MAX_CONCURRENT
        )
    return _refresh_semaphore


async def query_domain_metadata(
    value: str,
) -> GenericAppResult[DomainMetadata, AppError]:
    hostname = extract_hostname(value)
    if hostname is None:
        return GenericAppResult.failure(
            AppError(
                error_type=AppErrorType.BAD_REQUEST,
                error_message="URL metadata unavailable",
            )
        )

    domain = registered_domain(hostname)
    if domain is None:
        return GenericAppResult.failure(
            AppError(
                error_type=AppErrorType.BAD_REQUEST,
                error_message="URL metadata unavailable",
            )
        )

    cached = _metadata_cache.get(domain)
    if cached is not None:
        return GenericAppResult.success(cached)

    lock = _refresh_locks.setdefault(domain, asyncio.Lock())
    async with lock:
        cached = _metadata_cache.get(domain)
        if cached is not None:
            return GenericAppResult.success(cached)

        async with _get_refresh_semaphore():
            rdap_available, registration_date = await _query_rdap(domain)
            dns_status = await _query_dns(domain)

    metadata = DomainMetadata(
        domain=domain,
        rdap_available=rdap_available,
        dns_status=dns_status,
        registration_date=registration_date,
    )
    _metadata_cache[domain] = metadata
    _refresh_locks.pop(domain, None)
    return GenericAppResult.success(metadata)
