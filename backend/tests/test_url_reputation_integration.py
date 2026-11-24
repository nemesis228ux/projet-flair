import asyncio

import pytest

from app.integrations import url_reputation


class FakeResponse:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> object:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError("HTTP error")


def test_urlhaus_match(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        url_reputation.settings,
        "URLHAUS_ENABLED",
        True,
    )

    class FakeAsyncClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *args: object) -> None:
            del args

        async def post(self, *args: object, **kwargs: object) -> FakeResponse:
            del args, kwargs
            return FakeResponse(
                200,
                {
                    "query_status": "ok",
                    "urls": [{"url": "https://example.com/"}],
                },
            )

    monkeypatch.setattr(url_reputation.httpx, "AsyncClient", FakeAsyncClient)
    result = asyncio.run(
        url_reputation._check_urlhaus("example.com")
    )

    assert [match.code for match in result.matches] == ["URLHAUS_MATCH"]


def test_google_safe_browsing_match(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        url_reputation.settings,
        "GOOGLE_SAFE_BROWSING_API_KEY",
        "test-key",
    )

    class FakeAsyncClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *args: object) -> None:
            del args

        async def post(self, *args: object, **kwargs: object) -> FakeResponse:
            del args, kwargs
            return FakeResponse(
                200,
                {"matches": [{"threatType": "MALWARE"}]},
            )

    monkeypatch.setattr(url_reputation.httpx, "AsyncClient", FakeAsyncClient)
    result = asyncio.run(
        url_reputation._check_google_safe_browsing(
            "https://example.com"
        )
    )

    assert [match.code for match in result.matches] == [
        "GOOGLE_SAFE_BROWSING_MATCH"
    ]


def test_virustotal_malicious_match(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        url_reputation.settings,
        "VIRUSTOTAL_API_KEY",
        "test-key",
    )

    class FakeAsyncClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *args: object) -> None:
            del args

        async def post(self, *args: object, **kwargs: object) -> FakeResponse:
            del args, kwargs
            return FakeResponse(
                200,
                {"data": {"id": "test-analysis-id"}},
            )

        async def get(self, *args: object, **kwargs: object) -> FakeResponse:
            del args, kwargs
            return FakeResponse(
                200,
                {
                    "data": {
                        "attributes": {
                            "stats": {
                                "malicious": 3,
                                "suspicious": 1,
                            }
                        }
                    }
                },
            )

    monkeypatch.setattr(url_reputation.httpx, "AsyncClient", FakeAsyncClient)
    result = asyncio.run(
        url_reputation._check_virustotal("https://example.com")
    )

    assert [match.code for match in result.matches] == [
        "VIRUSTOTAL_MALICIOUS"
    ]
