import asyncio
import hashlib

import httpx
import pytest

from app.integrations import hibp


def test_hibp_sends_only_hash_prefix_and_adds_padding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = "example-test-password"
    password_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    expected_prefix = password_hash[:5]
    expected_suffix = password_hash[5:]
    request_values: dict[str, object] = {}
    request_headers: dict[str, str] = {}

    class FakeResponse:
        text = f"{expected_suffix}:42\n"

        def raise_for_status(self) -> None:
            return None

    class FakeAsyncClient:
        def __init__(self, *, timeout: float) -> None:
            request_values["timeout"] = timeout

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, url: str, *, headers: dict[str, str]) -> FakeResponse:
            request_values["url"] = url
            request_headers.update(headers)
            return FakeResponse()

    monkeypatch.setattr(hibp.httpx, "AsyncClient", FakeAsyncClient)

    result = asyncio.run(hibp.check_password_breach(password))

    assert result.is_success()
    assert result.data == 42
    assert request_values["url"] == f"{hibp._HIBP_RANGE_URL}{expected_prefix}"
    assert request_headers["Add-Padding"] == "true"
    assert password not in str(request_values["url"])


def test_hibp_reports_unavailable_for_invalid_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeResponse:
        text = "not-a-valid-response"

        def raise_for_status(self) -> None:
            return None

    class FakeAsyncClient:
        def __init__(self, *, timeout: float) -> None:
            pass

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, _url: str, *, headers: dict[str, str]) -> FakeResponse:
            return FakeResponse()

    monkeypatch.setattr(hibp.httpx, "AsyncClient", FakeAsyncClient)

    result = asyncio.run(hibp.check_password_breach("example"))

    assert result.is_error()
    assert "example" not in result.error.error_message
