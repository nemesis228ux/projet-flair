import re
from dataclasses import dataclass
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit

from app.schemas.analysis import Severity

_URL_PATTERN = re.compile(r"""(?i)(?:https?://|www\.)[^\s<>"'()]+""")
_URGENCY_PATTERN = re.compile(
    r"\b(urgent(?:ly)?|immediately|act now|d[eé]lai|tout de suite|"
    r"action requise|sans attendre|dans les \d+ heures)\b",
    re.IGNORECASE,
)
_CREDENTIAL_PATTERN = re.compile(
    r"\b(password|passcode|credentials|login details|verify your account|"
    r"mot de passe|identifiants|confirmez votre compte|v[eé]rifiez votre compte)\b",
    re.IGNORECASE,
)
_MONEY_PATTERN = re.compile(
    r"\b(wire transfer|bank transfer|send money|payment required|"
    r"virement|transfert d'argent|envoyez de l'argent|paiement requis)\b",
    re.IGNORECASE,
)
_GIFT_CARD_PATTERN = re.compile(
    r"\b(gift cards?|cartes? cadeaux?)\b", re.IGNORECASE
)
_VISIBLE_DOMAIN_PATTERN = re.compile(
    r"(?i)(?:https?://)?(?:www\.)?([a-z0-9.-]+\.[a-z0-9-]+)"
)


@dataclass(frozen=True)
class EmailSignal:
    code: str
    severity: Severity
    points: int


@dataclass(frozen=True)
class EmailLink:
    url: str
    label: str | None = None


@dataclass(frozen=True)
class EmailHeuristicAnalysis:
    signals: list[EmailSignal]
    links: list[EmailLink]


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[EmailLink] = []
        self._href: str | None = None
        self._label: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag.lower() == "a":
            self._href = next(
                (value for name, value in attrs if name.lower() == "href"), None
            )
            self._label = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._label.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href:
            label = "".join(self._label).strip()
            self.links.append(EmailLink(self._href.strip(), label or None))
            self._href = None
            self._label = []


def _extract_links(content: str) -> list[EmailLink]:
    parser = _AnchorParser()
    parser.feed(content)
    links = parser.links
    seen = {link.url for link in links}
    searchable_content = content
    for link in links:
        if link.label:
            searchable_content = searchable_content.replace(link.label, "", 1)

    for match in _URL_PATTERN.finditer(searchable_content):
        url = match.group().rstrip(".,;:!?")
        if url not in seen:
            links.append(EmailLink(url))
            seen.add(url)
    return links


def _domain(address_value: str | None) -> str | None:
    address = parseaddr(address_value or "")[1]
    if "@" not in address:
        return None
    return address.rsplit("@", maxsplit=1)[1].lower().rstrip(".")


def _host(url: str) -> str | None:
    candidate = url if "://" in url else f"//{url}"
    try:
        return (urlsplit(candidate).hostname or "").lower().removeprefix("www.") or None
    except ValueError:
        return None


def _has_link_mismatch(link: EmailLink) -> bool:
    if not link.label:
        return False
    visible_domain = _VISIBLE_DOMAIN_PATTERN.search(link.label)
    if visible_domain is None:
        return False
    destination = _host(link.url)
    visible = visible_domain.group(1).lower().removeprefix("www.")
    return destination is not None and destination != visible


def inspect_email(content: str) -> EmailHeuristicAnalysis:
    message = Parser(policy=policy.default).parsestr(content)
    signals: list[EmailSignal] = []
    links = _extract_links(content)

    if _URGENCY_PATTERN.search(content):
        signals.append(EmailSignal("EMAIL_URGENCY", Severity.MEDIUM, 15))
    if _CREDENTIAL_PATTERN.search(content):
        signals.append(EmailSignal("EMAIL_CREDENTIAL_REQUEST", Severity.HIGH, 30))
    if _MONEY_PATTERN.search(content):
        signals.append(EmailSignal("EMAIL_MONEY_REQUEST", Severity.HIGH, 30))
    if _GIFT_CARD_PATTERN.search(content):
        signals.append(EmailSignal("EMAIL_GIFT_CARD_REQUEST", Severity.HIGH, 30))

    if any(_has_link_mismatch(link) for link in links):
        signals.append(EmailSignal("EMAIL_LINK_MISMATCH", Severity.HIGH, 30))

    from_value = message.get("From")
    reply_to = message.get("Reply-To")
    from_domain = _domain(str(from_value)) if from_value is not None else None
    reply_domain = _domain(str(reply_to)) if reply_to is not None else None
    if from_domain and reply_domain and from_domain != reply_domain:
        signals.append(
            EmailSignal("EMAIL_REPLY_TO_MISMATCH", Severity.MEDIUM, 20)
        )

    authentication_results = " ".join(
        str(value) for value in message.get_all("Authentication-Results", [])
    ).casefold()
    received_spf = " ".join(
        str(value) for value in message.get_all("Received-SPF", [])
    ).casefold()
    authentication_failed = any(
        f"{check}=fail" in authentication_results
        for check in ("spf", "dkim", "dmarc")
    ) or "fail" in received_spf
    if authentication_failed:
        signals.append(
            EmailSignal("EMAIL_AUTHENTICATION_FAILURE", Severity.HIGH, 30)
        )

    return EmailHeuristicAnalysis(signals=signals, links=links)
