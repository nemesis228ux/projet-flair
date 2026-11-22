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

_IANA_RDAP_DNS_JSON_URL = "https://data.iana.org/rdap/dns.json"
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
_bootstrap_cache: TTLCache[
    str,
    tuple[tuple[tuple[str, ...], tuple[str, ...]], ...],
] = TTLCache(
    maxsize=16,
    ttl=settings.URL_METADATA_CACHE_TTL,
)
_refresh_locks: dict[str, asyncio.Lock] = {}
_bootstrap_locks: dict[str, asyncio.Lock] = {}
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
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
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


def _parse_rdap_services(
    payload: object,
) -> tuple[tuple[tuple[str, ...], tuple[str, ...]], ...]:
    if not isinstance(payload, dict):
        return ()
    services = payload.get("services")
    if not isinstance(services, list):
        return ()

    parsed_services: list[tuple[tuple[str, ...], tuple[str, ...]]] = []
    for service in services:
        if not isinstance(service, list) or len(service) != 2:
            continue
        suffix_payload = service[0]
        base_url_payload = service[1]
        if not isinstance(suffix_payload, list):
            continue
        if not isinstance(base_url_payload, list):
            continue

        suffixes = tuple(
            suffix.lower().rstrip(".").lstrip(".")
            for suffix in suffix_payload
            if isinstance(suffix, str)
            and suffix.lower().rstrip(".").lstrip(".")
        )
        base_urls = tuple(
            base_url.rstrip("/")
            for base_url in base_url_payload
            if isinstance(base_url, str) and base_url.rstrip("/")
        )
        if suffixes and base_urls:
            parsed_services.append((suffixes, base_urls))
    return tuple(parsed_services)


def _select_rdap_base_urls(
    domain: str,
    services: tuple[
        tuple[tuple[str, ...], tuple[str, ...]],
        ...,
    ],
) -> tuple[str, ...]:
    domain = domain.rstrip(".").lower()
    matches: list[
        tuple[int, tuple[str, ...], tuple[str, ...]]
    ] = []
    for suffixes, base_urls in services:
        matched_suffixes = [
            suffix
            for suffix in suffixes
            if domain == suffix or domain.endswith(f".{suffix}")
        ]
        if matched_suffixes:
            longest = max(len(suffix) for suffix in matched_suffixes)
            matches.append((longest, tuple(matched_suffixes), base_urls))

    if not matches:
        return ()
    longest = max(match[0] for match in matches)
    selected: list[str] = []
    for length, _suffixes, base_urls in matches:
        if length == longest:
            for base_url in base_urls:
                if base_url not in selected:
                    selected.append(base_url)
    return tuple(selected)


async def _download_rdap_bootstrap() -> tuple[
    tuple[tuple[str, ...], tuple[str, ...]],
    ...,
]:
    try:
        async with httpx.AsyncClient(
            timeout=settings.URL_METADATA_TIMEOUT,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.get(_IANA_RDAP_DNS_JSON_URL)
            if response.status_code != 200:
                return ()
            payload = response.json()
    except (httpx.HTTPError, ValueError):
        return ()
    return _parse_rdap_services(payload)


async def _get_rdap_bootstrap_services() -> tuple[
    tuple[tuple[str, ...], tuple[str, ...]],
    ...,
]:
    cached = _bootstrap_cache.get("services")
    if cached is not None:
        return cached

    lock = _bootstrap_locks.setdefault("services", asyncio.Lock())
    async with lock:
        cached = _bootstrap_cache.get("services")
        if cached is not None:
            return cached
        services = await _download_rdap_bootstrap()
        if services:
            _bootstrap_cache["services"] = services
        _bootstrap_locks.pop("services", None)
        return services


def _hostname_is_local_or_ip(hostname: str) -> bool:
    hostname = hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return not address.is_global


async def _validate_rdap_base_url(base_url: str) -> bool:
    try:
        parsed = urlsplit(base_url)
        if parsed.scheme.lower() != "https":
            return False
        if parsed.username is not None or parsed.password is not None:
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        parsed.port
        if parsed.query or parsed.fragment:
            return False
    except (TypeError, ValueError):
        return False

    hostname = hostname.rstrip(".").lower()
    if _hostname_is_local_or_ip(hostname):
        return False

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            records = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: socket.getaddrinfo(
                        hostname,
                        443,
                        type=socket.SOCK_STREAM,
                    ),
                ),
                timeout=settings.URL_METADATA_TIMEOUT,
            )
        except (socket.gaierror, asyncio.TimeoutError, OSError):
            return False

        resolved_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for record in records:
            try:
                resolved_addresses.append(
                    ipaddress.ip_address(record[4][0])
                )
            except ValueError:
                continue
        if not resolved_addresses:
            return False
        if any(not address.is_global for address in resolved_addresses):
            return False
    else:
        if not address.is_global:
            return False
    return True


async def _get_valid_rdap_base_urls(domain: str) -> tuple[str, ...]:
    services = await _get_rdap_bootstrap_services()
    selected = _select_rdap_base_urls(domain, services)

    valid: list[str] = []
    for base_url in selected:
        if await _validate_rdap_base_url(base_url):
            valid.append(base_url)
    return tuple(valid)


def _build_rdap_domain_url(base_url: str, domain: str) -> str:
    return (
        f"{base_url.rstrip('/')}/domain/"
        f"{quote(domain, safe='.')}"
    )


async def _query_rdap(domain: str) -> tuple[bool, datetime | None]:
    base_urls = await _get_valid_rdap_base_urls(domain)
    if not base_urls:
        return False, None

    try:
        async with httpx.AsyncClient(
            timeout=settings.URL_METADATA_TIMEOUT,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            for base_url in base_urls:
                try:
                    response = await client.get(
                        _build_rdap_domain_url(base_url, domain)
                    )
                    if response.status_code != 200:
                        continue
                    payload = response.json()
                except (httpx.HTTPError, ValueError):
                    continue
                return True, _parse_registration_date(payload)
    except httpx.HTTPError:
        return False, None
    return False, None


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

        try:
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
            return GenericAppResult.success(metadata)
        finally:
            _refresh_locks.pop(domain, None)
