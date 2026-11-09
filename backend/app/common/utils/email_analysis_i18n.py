"""
Traductions des messages de signal d'analyse d'email.

Chaque entrée fournit une explication compréhensible par l'utilisateur
en français et en anglais pour les signaux heuristiques détectés dans les emails.
"""

from __future__ import annotations

_MESSAGES: dict[str, dict[str, str]] = {
    "EMAIL_URGENCY": {
        "fr": (
            "L'email emploie un ton alarmiste ou pressant (ex: 'action requise', 'urgent', 'dans les 24h'), "
            "une technique classique visant à pousser la victime à agir sans réfléchir."
        ),
        "en": (
            "The email conveys an artificial sense of urgency (e.g. 'urgent action required', 'immediately'), "
            "a common tactic intended to rush the victim into acting without thinking."
        ),
    },
    "EMAIL_CREDENTIAL_REQUEST": {
        "fr": (
            "L'email demande la saisie ou la confirmation d'identifiants sensibles (mot de passe, code d'accès). "
            "Les organismes légitimes ne sollicitent jamais ces informations par email."
        ),
        "en": (
            "The email requests sensitive credentials or account verification (passwords, login details). "
            "Legitimate organizations never ask for your password via email."
        ),
    },
    "EMAIL_MONEY_REQUEST": {
        "fr": (
            "L'email réclame un transfert d'argent, un paiement immédiat ou un virement bancaire suspect."
        ),
        "en": (
            "The email requests a wire transfer, money transaction, or immediate payment."
        ),
    },
    "EMAIL_GIFT_CARD_REQUEST": {
        "fr": (
            "L'email demande l'achat ou l'envoi de cartes cadeaux, un mode de paiement très prisé des escrocs "
            "en raison de son caractère intraçable et irréversible."
        ),
        "en": (
            "The email requests gift cards, a common method used by scammers because it is untraceable and irreversible."
        ),
    },
    "EMAIL_LINK_MISMATCH": {
        "fr": (
            "Le texte visible du lien affiche une adresse différente du site réel vers lequel il pointe "
            "(tentative manifeste de tromperie visuelle)."
        ),
        "en": (
            "The visible link text displays a different domain from the actual destination URL "
            "(clear sign of deceptive phishing)."
        ),
    },
    "EMAIL_REPLY_TO_MISMATCH": {
        "fr": (
            "L'adresse de réponse (Reply-To) ne correspond pas au domaine de l'expéditeur (From). "
            "Vos réponses seraient redirigées vers un serveur tiers."
        ),
        "en": (
            "The reply address (Reply-To) does not match the sender's domain (From). "
            "Your responses would be redirected to a third party."
        ),
    },
    "EMAIL_AUTHENTICATION_FAILURE": {
        "fr": (
            "L'email a échoué aux contrôles d'authenticité (SPF, DKIM ou DMARC). "
            "L'identité de l'expéditeur est très probablement falsifiée (usurpation)."
        ),
        "en": (
            "The email failed security authentication checks (SPF, DKIM, or DMARC). "
            "The sender address is likely spoofed."
        ),
    },
    "EMAIL_BRAND_IMPERSONATION": {
        "fr": (
            "L'email ou un lien inclus utilise un nom de domaine imitant visuellement une marque reconnue (typosquattage)."
        ),
        "en": (
            "The email or an included link uses a domain name that closely mimics a well-known brand (typosquatting)."
        ),
    },
    "EMAIL_UNSOLICITED_SOLICITATION": {
        "fr": (
            "L'email contient une proposition commerciale ou une demande de collaboration non sollicitée."
        ),
        "en": (
            "The email contains an unsolicited commercial offer or collaboration request."
        ),
    },
    "EMAIL_FINANCIAL_INCENTIVE": {
        "fr": (
            "Une rémunération ou une récompense financière est utilisée pour inciter à accepter la demande."
        ),
        "en": (
            "A payment or financial reward is used to encourage acceptance of the request."
        ),
    },
    "EMAIL_SENSITIVE_DATA_REQUEST": {
        "fr": (
            "L'email demande des données sensibles ou propriétaires, par exemple du code source privé."
        ),
        "en": (
            "The email requests sensitive or proprietary data, such as private source code."
        ),
    },
}

_FALLBACK_LANG = "fr"


def get_email_signal_detail(code: str, lang: str) -> str | None:
    """
    Retourne le message localisé pour un code de signal heuristique d'email.

    - `lang`: langue cible ("fr" ou "en") ; repli sur FR si inconnue.
    """
    translations = _MESSAGES.get(code)
    if not translations:
        return None
    return translations.get(lang) or translations.get(_FALLBACK_LANG)
