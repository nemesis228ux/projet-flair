import asyncio
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from app.common.app_result import GenericAppResult
from app.common.business_error import AppError, AppErrorType
from app.core.config import settings

_RDAP_BOOTSTRAP_URL = "https://rdap-bootstrap.iana.org/domain/"


@dataclass(frozen=True)
class DomainMetadata:
    domain: str
    rdap_available: bool = False
    dns_available: bool = False
    tls_available: bool = False
    registration_date: datetime | None = None
    certificate_not_before: datetime | None = None


def _registered_domain(hostname: str) -> str | None:
    host = hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass

    if host in {"localhost"} or host.endswith(".localhost"):
        return None

    labels = host.split(".")
    compound_suffixes = {"co.uk", "com.au", "co.jp", "com.br", "co.in"}
    if len(labels) >= 3 and ".".join(labels[-2:]) in compound_suffixes:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else None


def extract_hostname(value: str) -> str | None:
    try:
        parsed = urlsplit(value if "://" in value else f"//{value}")
        hostname = parsed.hostname
    except ValueError:
        return None
    if not hostname:
        return None
    return hostname.rstrip(".").lower()


def _is_public_host(hostname: str) -> bool:
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        hostname = hostname.rstrip(".").lower()
        return (
            bool(hostname)
            and hostname != "localhost"
            and not hostname.endswith(".localhost")
            and "." in hostname
        )
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _parse_registration_date(payload: object) -> datetime | None:
    if not isinstance(payload, dict):
        return None
    events = payload.get("events")
    if not isinstance(events, list):
        return None
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("eventAction") not in {
            "registration",
            "registered",
        }:
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
            follow_redirects=True,
        ) as client:
            response = await client.get(f"{_RDAP_BOOTSTRAP_URL}{domain}")
            if response.status_code != 200:
                return False, None
            payload = response.json()
    except (httpx.HTTPError, ValueError):
        return False, None
    return True, _parse_registration_date(payload)


async def _query_dns(domain: str) -> bool:
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
        for record in records:
            sockaddr = record[4]
            address = sockaddr[0] if isinstance(sockaddr, tuple) else str(sockaddr)
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue
            if _is_public_host(address):
                return True
        return False
    except (asyncio.TimeoutError, socket.gaierror):
        return False


async def _query_tls(domain: str) -> tuple[bool, datetime | None]:
    context = ssl.create_default_context()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                domain,
                443,
                ssl=context,
                server_hostname=domain,
            ),
            timeout=settings.URL_METADATA_TIMEOUT,
        )
        del reader
        try:
            certificate = writer.get_extra_info("peercert")
            if not isinstance(certificate, dict):
                return False, None
            value = certificate.get("notBefore")
            if not isinstance(value, str):
                return False, None
            try:
                parsed = datetime.strptime(
                    value,
                    "%b %d %H:%M:%S %Y %Z",
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                return False, None
            return True, parsed
        finally:
            writer.close()
            await writer.wait_closed()
    except OSError:
        return False, None


async def query_domain_metadata(
    value: str,
) -> GenericAppResult[DomainMetadata, AppError]:
    hostname = extract_hostname(value)
    if hostname is None or not _is_public_host(hostname):
        return GenericAppResult.failure(
            AppError(
                error_type=AppErrorType.BAD_REQUEST,
                error_message="URL metadata unavailable",
            )
        )

    domain = _registered_domain(hostname)
    if domain is None:
        return GenericAppResult.failure(
            AppError(
                error_type=AppErrorType.BAD_REQUEST,
                error_message="URL metadata unavailable",
            )
        )

    rdap_task = _query_rdap(domain)
    dns_task = _query_dns(domain)
    tls_task = _query_tls(domain)
    rdap_result, dns_available, tls_result = await asyncio.gather(
        rdap_task,
        dns_task,
        tls_task,
    )
    rdap_available, registration_date = rdap_result
    tls_available, certificate_not_before = tls_result

    return GenericAppResult.success(
        DomainMetadata(
            domain=domain,
            rdap_available=rdap_available,
            dns_available=dns_available,
            tls_available=tls_available,
            registration_date=registration_date,
            certificate_not_before=certificate_not_before,
        )
    )
