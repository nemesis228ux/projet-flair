"""
Traductions des messages de signal d'analyse d'URL.

Chaque entrée peut contenir un placeholder `{detail}` qui sera remplacé
par la valeur dynamique portée par le champ `detail` du `UrlRiskSignal`
(ex. le TLD, le nombre de sous-domaines, la longueur d'URL, le nom du param).
"""

from __future__ import annotations

_MESSAGES: dict[str, dict[str, str]] = {
    "MISSING_HTTPS": {
        "fr": (
            "La connexion n'est pas chiffrée (HTTP ou schéma absent). "
            "Les données échangées avec cette URL peuvent être interceptées."
        ),
        "en": (
            "Connection is not encrypted (HTTP or missing scheme). "
            "Data exchanged with this URL can be intercepted."
        ),
    },
    "URL_USERINFO": {
        "fr": (
            "L'URL intègre des identifiants (utilisateur:mot_de_passe@hôte), "
            "une technique d'hameçonnage classique pour usurper l'identité d'un domaine de confiance."
        ),
        "en": (
            "URL embeds credentials (user:password@host), "
            "a classic phishing trick to impersonate a trusted domain."
        ),
    },
    "AT_IN_PATH": {
        "fr": (
            "Le caractère '@' dans le chemin ou la requête de l'URL peut induire "
            "les utilisateurs en erreur sur le domaine réellement visité."
        ),
        "en": (
            "The '@' character in the URL path or query can mislead users "
            "into thinking they are visiting a different domain."
        ),
    },
    "PUNYCODE_DOMAIN": {
        "fr": (
            "Le domaine utilise des caractères internationalisés (IDN/Punycode), "
            "qui peuvent être exploités pour des attaques par homographe."
        ),
        "en": (
            "Domain uses internationalized characters (IDN/Punycode), "
            "which can be used for homograph attacks."
        ),
    },
    "TYPOSQUATTING": {
        "fr": (
            "Le nom de domaine ressemble fortement à une marque connue, "
            "ce qui suggère une tentative d'usurpation d'identité."
        ),
        "en": (
            "Domain name closely resembles a well-known brand, "
            "suggesting a possible impersonation attempt."
        ),
    },
    "SUSPICIOUS_TLD": {
        "fr": (
            "Le domaine de premier niveau '.{detail}' est fréquemment associé "
            "à des sites malveillants ou de mauvaise qualité."
        ),
        "en": (
            "The top-level domain '.{detail}' is frequently associated "
            "with malicious or low-quality sites."
        ),
    },
    "URL_SHORTENER": {
        "fr": "Les services de raccourcissement d'URL dissimulent la véritable destination du lien.",
        "en": "URL shortening services conceal the true destination of a link.",
    },
    "MANY_SUBDOMAINS": {
        "fr": (
            "Le domaine comporte {detail} niveaux de sous-domaines, "
            "ce qui est inhabituel et peut indiquer une tentative d'obfuscation."
        ),
        "en": (
            "The domain has {detail} subdomain levels, "
            "which is unusual and may indicate obfuscation."
        ),
    },
    "IP_ADDRESS_HOST": {
        "fr": (
            "L'URL utilise une adresse IP brute au lieu d'un nom de domaine, "
            "ce qui est inhabituel pour un site légitime."
        ),
        "en": (
            "The URL uses a raw IP address instead of a domain name, "
            "which is unusual for legitimate websites."
        ),
    },
    "MALFORMED_URL": {
        "fr": "L'URL est malformée ou ne peut pas être analysée : aucun nom d'hôte valide n'a été trouvé.",
        "en": "The URL is malformed or cannot be parsed: no valid hostname was found.",
    },
    "UNSUPPORTED_URL_SCHEME": {
        "fr": (
            "L'URL utilise un protocole non web (ex. javascript:, data:, file:) "
            "pouvant exécuter du code ou accéder à des fichiers locaux."
        ),
        "en": (
            "The URL uses a non-web scheme (e.g. javascript:, data:, file:) "
            "that can execute code or access local files."
        ),
    },
    "SUSPICIOUS_KEYWORD": {
        "fr": (
            "L'URL contient des mots-clés couramment utilisés dans les pages d'hameçonnage "
            "(ex. login, verify, secure, password)."
        ),
        "en": (
            "The URL contains keywords commonly used in phishing pages "
            "(e.g. login, verify, secure, password)."
        ),
    },
    "LONG_URL": {
        "fr": (
            "L'URL est anormalement longue ({detail} caractères), "
            "ce qui peut servir à masquer la véritable destination."
        ),
        "en": (
            "The URL is unusually long ({detail} characters), "
            "which can be used to hide the true destination."
        ),
    },
    "OPEN_REDIRECT_PARAM": {
        "fr": (
            "Le paramètre '{detail}' peut rediriger les utilisateurs "
            "vers une URL externe malveillante."
        ),
        "en": (
            "Query parameter '{detail}' may redirect users "
            "to a malicious external URL."
        ),
    },
}

_FALLBACK_LANG = "fr"


def get_signal_detail(code: str, lang: str, detail: str | None = None) -> str | None:
    """
    Retourne le message localisé pour un code de signal donné.

    - `lang`   : langue cible ("fr" ou "en") ; repli sur FR si inconnue.
    - `detail` : valeur dynamique à injecter dans le template (ex. TLD, longueur…).
    """
    translations = _MESSAGES.get(code)
    if not translations:
        return None
    template = translations.get(lang) or translations.get(_FALLBACK_LANG)
    if not template:
        return None
    try:
        return template.format(detail=detail) if detail is not None else template
    except KeyError:
        return template

