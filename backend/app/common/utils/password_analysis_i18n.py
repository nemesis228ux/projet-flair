"""
Traductions des messages de signal d'analyse de mot de passe.

Le placeholder `{detail}` est injecté dynamiquement quand la valeur est disponible
(ex. : le nombre d'occurrences dans les fuites pour BREACHED).
"""

from __future__ import annotations

_MESSAGES: dict[str, dict[str, str]] = {
    "PASSWORD_TOO_SHORT": {
        "fr": (
            "Le mot de passe est trop court (moins de 8 caractères). "
            "Un mot de passe court est vulnérable aux attaques par force brute."
        ),
        "en": (
            "The password is too short (less than 8 characters). "
            "Short passwords are highly vulnerable to brute-force attacks."
        ),
    },
    "PASSWORD_WEAK": {
        "fr": (
            "Le mot de passe est trop facile à deviner. "
            "Utilisez une combinaison de lettres majuscules et minuscules, "
            "de chiffres et de caractères spéciaux."
        ),
        "en": (
            "The password is too easy to guess. "
            "Use a mix of uppercase and lowercase letters, "
            "numbers, and special characters."
        ),
    },
    "BREACHED": {
        "fr": (
            "Ce mot de passe a été trouvé {detail} fois dans des bases de données "
            "de fuites publiques. Il ne doit plus jamais être utilisé."
        ),
        "en": (
            "This password appeared {detail} times in known public data breaches. "
            "It must never be used again."
        ),
    },
}

_FALLBACK_LANG = "fr"


def get_password_signal_detail(
    code: str, lang: str, detail: str | None = None
) -> str | None:
    """
    Retourne le message localisé pour un code de signal de mot de passe.

    - `lang`   : langue cible ("fr" ou "en") ; repli sur FR si inconnue.
    - `detail` : valeur dynamique à injecter dans le template (ex. : nombre de fuites).
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
