import ipaddress
import math
import re
from dataclasses import dataclass
from urllib.parse import ParseResult, parse_qs, unquote, urlsplit

from rapidfuzz import fuzz
from rapidfuzz.distance import DamerauLevenshtein

from app.schemas.analysis import Severity

_BRANDS = (
    "amazon",
    "apple",
    "airtel",
    "coris",
    "dropbox",
    "ecobank",
    "facebook",
    "free",
    "google",
    "instagram",
    "linkedin",
    "microsoft",
    "mixx",
    "moov",
    "mtn",
    "netflix",
    "orange",
    "paypal",
    "safaricom",
    "sonatel",
    "telecel",
    "tigo",
    "togocom",
    "uba",
    "vodacom",
    "whatsapp",
    "wave",
    "yas",
    "mpesa",
    "tmoney",
    "flooz",
)
_SHORTENERS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
}
_SUSPICIOUS_TLDS = {
    "cf",
    "click",
    "country",
    "download",
    "ga",
    "gq",
    "loan",
    "men",
    "ml",
    "mov",
    "stream",
    "tk",
    "top",
    "work",
    "buzz",
    "xyz",
    "zip",
}
_SUSPICIOUS_WORDS = {
    "account",
    "billing",
    "login",
    "password",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
}
_COMPOUND_SUFFIXES = {"co.uk", "com.au", "co.jp", "com.br", "co.in"}
_DIGIT_SUBSTITUTIONS = str.maketrans(
    {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"}
)
# Query parameter names commonly abused for open-redirect attacks
_OPEN_REDIRECT_PARAMS = {
    "url", "redirect", "redirect_url", "redirect_uri", "next",
    "goto", "return", "returnto", "return_url", "target", "dest",
    "destination", "forward", "link", "ref",
}
_TRACKING_PARAMS = {
    "_gl",
    "_hsenc",
    "_hsmi",
    "_t",
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "msclkid",
    "trk",
    "utm_campaign",
    "utm_medium",
    "utm_source",
    "pid",
    "guid",
    "key",
    "sid",
    "s",
    "campaign",
    "ref",
    "partner",
}
_OPAQUE_PATH_TOKEN = re.compile(r"^[A-Za-z0-9]{7,}$")
_TIMESTAMP_PARAM = re.compile(r"^_t\d{8,}$")
_TEMPORARY_PAGE_PATH = re.compile(
    r"\.(?:html?|php|aspx?|jsp)(?:$|[/?])",
    re.IGNORECASE,
)
_NUMERIC_TRACKING_VALUE = re.compile(r"^\d{12,}$")


@dataclass(frozen=True)
class UrlRiskSignal:
    code: str
    severity: Severity
    points: int
    detail: str | None = None


def _signal(code: str, severity: Severity, points: int, detail: str | None = None) -> UrlRiskSignal:
    return UrlRiskSignal(code=code, severity=severity, points=points, detail=detail)


def _domain_label(host: str) -> str:
    labels = host.rstrip(".").split(".")
    suffix = ".".join(labels[-2:])
    if suffix in _COMPOUND_SUFFIXES and len(labels) >= 3:
        return labels[-3]
    return labels[-2] if len(labels) >= 2 else labels[0]


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _is_randomized_domain(domain_label: str) -> bool:
    normalized = re.sub(r"[^a-z0-9-]", "", domain_label.lower())
    if not normalized:
        return False

    parts = [part for part in normalized.split("-") if part]
    if len(normalized) >= 14 and len(parts) >= 2:
        return True
    if len(normalized) >= 12 and _shannon_entropy(normalized) >= 3.2:
        return True
    if len(normalized) >= 6:
        digit_count = sum(character.isdigit() for character in normalized)
        letter_count = sum(character.isalpha() for character in normalized)
        if digit_count >= 2 and digit_count / (digit_count + letter_count) >= 0.25:
            return True
    return False


def _is_typosquatting(domain_label: str) -> bool:
    candidates: list[str] = [domain_label, *re.split(r"[-_]", domain_label)]
    for candidate in candidates:
        for brand in _BRANDS:
            if candidate == brand:
                continue
            normalized = candidate.translate(_DIGIT_SUBSTITUTIONS)
            is_close_match = fuzz.ratio(normalized, brand) >= 86
            is_transposed_match = (
                len(brand) >= 4
                and len(normalized) == len(brand)
                and DamerauLevenshtein.distance(normalized, brand) == 1
            )
            if is_close_match or is_transposed_match:
                return True
    return False


def _has_unsupported_scheme(value: str) -> bool:
    scheme_match = re.match(r"^([a-z][a-z0-9+.-]*):", value, re.IGNORECASE)
    if not scheme_match:
        return False
    scheme = scheme_match.group(1).lower()
    has_authority = value[scheme_match.end() :].startswith("//")
    return scheme not in {"http", "https"} and (
        has_authority or scheme in {"data", "file", "javascript", "mailto"}
    )


def _parse_url(value: str) -> ParseResult | None:
    has_web_scheme = value.lower().startswith(("http://", "https://"))
    if has_web_scheme:
        candidate = value
    else:
        candidate = value if value.startswith("//") else f"//{value}"
    try:
        parsed = urlsplit(candidate)
        parsed.hostname
        parsed.port
    except ValueError:
        return None
    return parsed


def _inspect_domain(host_ascii: str) -> list[UrlRiskSignal]:
    signals: list[UrlRiskSignal] = []
    labels = host_ascii.rstrip(".").split(".")
    if any(label.startswith("xn--") for label in labels):
        signals.append(_signal("PUNYCODE_DOMAIN", Severity.MEDIUM, 25))
    if _is_typosquatting(_domain_label(host_ascii)):
        signals.append(_signal("TYPOSQUATTING", Severity.HIGH, 35))
    if _is_randomized_domain(_domain_label(host_ascii)):
        signals.append(
            _signal(
                "RANDOMIZED_DOMAIN",
                Severity.MEDIUM,
                20,
                detail=_domain_label(host_ascii),
            )
        )
    if labels[-1] in _SUSPICIOUS_TLDS:
        signals.append(_signal("SUSPICIOUS_TLD", Severity.MEDIUM, 15, detail=labels[-1]))
    registrable = ".".join(labels[-2:]) if len(labels) >= 2 else host_ascii
    if host_ascii in _SHORTENERS or registrable in _SHORTENERS:
        signals.append(_signal("URL_SHORTENER", Severity.LOW, 10))
    if len(labels) > 4:
        signals.append(_signal("MANY_SUBDOMAINS", Severity.LOW, 8, detail=str(len(labels) - 1)))
    return signals


def _inspect_host(host: str, parsed: ParseResult) -> list[UrlRiskSignal]:
    signals: list[UrlRiskSignal] = []

    effective_scheme = parsed.scheme.lower() if parsed.scheme else ""
    if effective_scheme != "https":
        signals.append(_signal("MISSING_HTTPS", Severity.MEDIUM, 25))

    if parsed.username is not None or parsed.password is not None:
        signals.append(_signal("URL_USERINFO", Severity.MEDIUM, 25))

    raw_path_query = (parsed.path or "") + (f"?{parsed.query}" if parsed.query else "")
    if "@" in raw_path_query:
        signals.append(_signal("AT_IN_PATH", Severity.MEDIUM, 20))

    try:
        host_ascii = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return signals + [_signal("MALFORMED_URL", Severity.HIGH, 40)]

    try:
        ipaddress.ip_address(host_ascii)
    except ValueError:
        signals.extend(_inspect_domain(host_ascii))
    else:
        signals.append(_signal("IP_ADDRESS_HOST", Severity.MEDIUM, 25))
    return signals


def _inspect_query(query: str) -> list[UrlRiskSignal]:
    """Detect open-redirect patterns in query parameters."""
    if not query:
        return []
    signals: list[UrlRiskSignal] = []
    try:
        params = parse_qs(query, keep_blank_values=True)
    except Exception:
        return signals
    for param_name in params:
        if param_name.lower() in _OPEN_REDIRECT_PARAMS:
            signals.append(_signal("OPEN_REDIRECT_PARAM", Severity.MEDIUM, 20, detail=param_name))
            break  
    if any(
        param_name.lower() in _TRACKING_PARAMS
        or _TIMESTAMP_PARAM.fullmatch(param_name.lower())
        for param_name in params
    ):
        signals.append(_signal("TRACKING_PARAMETER", Severity.LOW, 5))
    if any(
        _NUMERIC_TRACKING_VALUE.fullmatch(value)
        for values in params.values()
        for value in values
    ) or any(
        _NUMERIC_TRACKING_VALUE.fullmatch(param_name)
        for param_name in params
    ):
        signals.append(_signal("CAMPAIGN_TRACKING_VALUE", Severity.MEDIUM, 12))
    return signals


def _inspect_path(path: str) -> list[UrlRiskSignal]:
    segments = [segment for segment in path.split("/") if segment]
    signals: list[UrlRiskSignal] = []
    if _TEMPORARY_PAGE_PATH.search(path):
        signals.append(
            _signal("TEMPORARY_PAGE_PATH", Severity.MEDIUM, 16, detail=path)
        )
    opaque_segments = [
        segment
        for segment in segments
        if _OPAQUE_PATH_TOKEN.fullmatch(segment)
        and any(character.isalpha() for character in segment)
        and (
            any(character.isdigit() for character in segment)
            or any(character.isupper() for character in segment)
        )
    ]
    if len(opaque_segments) >= 1:
        signals.append(
            _signal(
                "OPAQUE_PATH_TOKEN",
                Severity.MEDIUM,
                20,
                detail=str(len(opaque_segments)),
            )
        )
    return signals


def inspect_url(url: str) -> list[UrlRiskSignal]:
    """Extract explainable risk signals from a URL string without contacting it."""
    value = url.strip()
    if not value or any(character.isspace() for character in value):
        return [_signal("MALFORMED_URL", Severity.HIGH, 40)]
    if _has_unsupported_scheme(value):
        return [_signal("UNSUPPORTED_URL_SCHEME", Severity.HIGH, 35)]

    parsed = _parse_url(value)
    if parsed is None or not parsed.hostname:
        return [_signal("MALFORMED_URL", Severity.HIGH, 40)]

    signals = _inspect_host(parsed.hostname, parsed)
    signals.extend(_inspect_path(parsed.path))
    signals.extend(_inspect_query(parsed.query))

    inspected_text = unquote(f"{parsed.hostname}{parsed.path}").lower()
    if any(word in inspected_text for word in _SUSPICIOUS_WORDS):
        signals.append(_signal("SUSPICIOUS_KEYWORD", Severity.LOW, 8))

    if len(value) >= 150:
        signals.append(_signal("LONG_URL", Severity.LOW, 5, detail=str(len(value))))

    return signals
