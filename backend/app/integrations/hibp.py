import hashlib

import httpx

from app.common.app_result import GenericAppResult
from app.common.business_error import AppError, AppErrorType
from app.common.constants.messages import Messages

_HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"
_USER_AGENT = "FlairPasswordChecker/1.0"


def _unavailable_error() -> AppError:
    return AppError(
        error_type=AppErrorType.UNKNOWN_ERROR,
        error_message=Messages.PASSWORD_BREACH_CHECK_UNAVAILABLE,
    )


def _parse_breach_count(response_text: str, expected_suffix: str) -> int | None:
    if not response_text:
        return None

    breach_count = 0
    for line in response_text.splitlines():
        parts = line.split(":")
        if len(parts) != 2:
            return None

        suffix, count_text = parts
        if (
            len(suffix) != 35
            or any(character not in "0123456789ABCDEF" for character in suffix)
        ):
            return None

        try:
            count = int(count_text)
        except ValueError:
            return None
        if count < 0:
            return None

        if suffix == expected_suffix:
            breach_count = count

    return breach_count


async def check_password_breach(
    password: str,
) -> GenericAppResult[int, AppError]:
    password_hash = hashlib.sha1(
        password.encode("utf-8"), usedforsecurity=False
    ).hexdigest().upper()
    prefix, suffix = password_hash[:5], password_hash[5:]

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                f"{_HIBP_RANGE_URL}{prefix}",
                headers={
                    "Add-Padding": "true",
                    "User-Agent": _USER_AGENT,
                },
            )
            response.raise_for_status()
    except httpx.HTTPError:
        return GenericAppResult.failure(_unavailable_error())

    breach_count = _parse_breach_count(response.text, suffix)
    if breach_count is None:
        return GenericAppResult.failure(_unavailable_error())

    return GenericAppResult.success(breach_count)
