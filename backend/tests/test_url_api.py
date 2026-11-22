from datetime import datetime, timedelta, timezone
import asyncio

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.common.utils.url_analysis import inspect_url
from app.integrations.domain_metadata import DomainMetadata
from app.main import app
from app.repositories import CrudResult
from app.services.url_analysis_service import UrlAnalysisService

client = TestClient(app)


@pytest.fixture(autouse=True)
def disable_domain_metadata(monkeypatch):
    monkeypatch.setattr(settings, "URL_METADATA_ENABLED", False)


def test_url_analysis_uses_the_submitted_url_and_shared_wrapper() -> None:
    response = client.post(
        "/api/v1/url/analyze",
        json={"url": "https://example.com", "lang": "en"},
    )

    assert response.status_code == 200
    assert response.json()["success"] is True
    assert response.json()["result"] == {
        "score": 0,
        "verdict": "safe",
        "reasons": [],
        "sources": ["heuristics"],
        "tactics": None,
        "explanation": None,
        "breach_count": None,
    }


def test_url_analysis_reports_suspicious_url_signals() -> None:
    response = client.post(
        "/api/v1/url/analyze",
        json={"url": "http://paypa1-login.xyz/verify", "lang": "en"},
    )

    assert response.status_code == 200
    result = response.json()["result"]
    assert result["verdict"] == "dangerous"
    assert result["score"] >= 60
    assert {reason["code"] for reason in result["reasons"]} >= {
        "MISSING_HTTPS",
        "TYPOSQUATTING",
        "SUSPICIOUS_TLD",
        "SUSPICIOUS_KEYWORD",
    }


def test_url_analysis_reports_opaque_campaign_tokens() -> None:
    response = client.post(
        "/api/v1/url/analyze",
        json={
            "url": (
                "https://waev-perks.com/cihwP5T16NU/"
                "VPg01gT3I2Vgb1EKllRUbea465?_t1794092503676"
            ),
            "lang": "en",
        },
    )

    assert response.status_code == 200
    result = response.json()["result"]
    assert result["verdict"] == "dangerous"
    assert result["score"] >= 60
    assert {reason["code"] for reason in result["reasons"]} >= {
        "OPAQUE_PATH_TOKEN",
        "TRACKING_PARAMETER",
    }


def test_url_analysis_reports_wave_typosquatting() -> None:
    response = client.post(
        "/api/v1/url/analyze",
        json={
            "url": (
                "https://waev-perks.com/cihwP5T16NU/"
                "VPg01gT3I2Vgb1EKllRUbea465?_t1794092503676"
            ),
            "lang": "en",
        },
    )

    assert response.status_code == 200
    result = response.json()["result"]
    assert result["verdict"] == "dangerous"
    assert result["score"] >= 60
    assert "TYPOSQUATTING" in {
        reason["code"] for reason in result["reasons"]
    }


def test_url_analysis_reports_african_brand_typosquatting() -> None:
    for url in (
        "https://moove-africa.com/login",
        "https://mixxx-money.com/verify",
        "https://togoocom.com/account",
    ):
        result_codes = {signal.code for signal in inspect_url(url)}
        assert "TYPOSQUATTING" in result_codes


def test_url_analysis_metadata_signals_recent_domain() -> None:
    now = datetime.now(timezone.utc)
    signals = UrlAnalysisService._metadata_signals(
        DomainMetadata(
            domain="earumora-kuytbe.xyz",
            rdap_available=True,
            dns_available=True,
            tls_available=True,
            registration_date=now - timedelta(days=3),
            certificate_not_before=now - timedelta(days=2),
        )
    )

    codes = {signal.code for signal in signals}
    assert "DOMAIN_TOO_NEW" in codes
    assert "NEW_TLS_CERTIFICATE" in codes


def test_url_analysis_metadata_signals_unresolved_domain() -> None:
    signals = UrlAnalysisService._metadata_signals(
        DomainMetadata(
            domain="missing-domain.example",
            rdap_available=False,
            dns_available=False,
            tls_available=False,
        )
    )

    assert "DNS_UNRESOLVED" in {
        signal.code for signal in signals
    }


def test_url_analysis_combines_metadata_sources(monkeypatch) -> None:
    class FakeMetadataRepository:
        async def inspect(self, url: str):
            del url
            return CrudResult.crud_success(
                DomainMetadata(
                    domain="example.com",
                    rdap_available=True,
                    dns_available=True,
                    tls_available=True,
                    registration_date=(
                        datetime.now(timezone.utc) - timedelta(days=3)
                    ),
                    certificate_not_before=(
                        datetime.now(timezone.utc) - timedelta(days=2)
                    ),
                )
            )

    monkeypatch.setattr(settings, "URL_METADATA_ENABLED", True)
    service = UrlAnalysisService(
        metadata_repository=FakeMetadataRepository()
    )
    result = asyncio.run(
        service.analyze("https://example.com", lang="en")
    )
    payload = result.data

    assert "rdap" in payload.sources
    assert "dns" in payload.sources
    assert "tls" in payload.sources


def test_url_analysis_reports_campaign_and_temporary_links() -> None:
    cases = (
        (
            "https://earumora-kuytbe.xyz/CDMNBVCXZLKJCD.html"
            "?pid=r_917624934242571",
            {"SUSPICIOUS_TLD", "TRACKING_PARAMETER"},
        ),
        (
            "https://pdd.tg.999yes.xyz/tg/?guid=1007326&key=friend",
            {"SUSPICIOUS_TLD", "TRACKING_PARAMETER"},
        ),
        (
            "https://earndfre-cduwbd.xyz/TGMNBVCXZLKJTG.html"
            "?pid=r_917647150626626",
            {"SUSPICIOUS_TLD", "TRACKING_PARAMETER"},
        ),
        (
            "https://casajoys.com/cdc60ak",
            {"OPAQUE_PATH_TOKEN"},
        ),
        (
            "https://wljra.buzz/UaviraNZvR/gh-fr?"
            "1221970658904224237&s=wa&",
            {
                "SUSPICIOUS_TLD",
                "TRACKING_PARAMETER",
                "CAMPAIGN_TRACKING_VALUE",
            },
        ),
    )

    for url, expected_codes in cases:
        signals = inspect_url(url)
        score = sum(signal.points for signal in signals)
        codes = {signal.code for signal in signals}

        assert score >= 20, (url, score, codes)
        assert expected_codes <= codes, (url, expected_codes, codes)


def test_url_analysis_does_not_flag_ordinary_paths_and_values() -> None:
    ordinary_urls = (
        "https://example-company.com/index.html",
        "https://example.com/Welcome",
        "https://example.com/products/dashboard",
        "https://example.com/order?order_id=123456789012",
    )

    for url in ordinary_urls:
        codes = {signal.code for signal in inspect_url(url)}
        assert "RANDOMIZED_DOMAIN" not in codes
        assert "TEMPORARY_PAGE_PATH" not in codes
        assert "OPAQUE_PATH_TOKEN" not in codes
        assert "CAMPAIGN_TRACKING_VALUE" not in codes


def test_url_analysis_validates_input_length() -> None:
    response = client.post(
        "/api/v1/url/analyze",
        json={"url": "x" * 2049, "lang": "en"},
    )

    assert response.status_code == 422
    assert response.json()["success"] is False
