import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import ParseResult, parse_qs, unquote, urlsplit

from rapidfuzz import fuzz

from app.schemas.analysis import Severity

_BRANDS = (
    "amazon",
    "apple",
    "dropbox",
    "facebook",
    "google",
    "instagram",
    "linkedin",
    "microsoft",
    "netflix",
    "paypal",
    "whatsapp",
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


def _is_typosquatting(domain_label: str) -> bool:
    candidates: list[str] = [domain_label, *re.split(r"[-_]", domain_label)]
    for candidate in candidates:
        for brand in _BRANDS:
            if candidate == brand:
                continue
            normalized = candidate.translate(_DIGIT_SUBSTITUTIONS)
            if fuzz.ratio(normalized, brand) >= 86:
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
    signals.extend(_inspect_query(parsed.query))

    inspected_text = unquote(f"{parsed.hostname}{parsed.path}").lower()
    if any(word in inspected_text for word in _SUSPICIOUS_WORDS):
        signals.append(_signal("SUSPICIOUS_KEYWORD", Severity.LOW, 8))

    if len(value) >= 150:
        signals.append(_signal("LONG_URL", Severity.LOW, 5, detail=str(len(value))))

    return signals
