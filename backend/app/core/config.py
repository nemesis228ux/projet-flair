from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str
    ENV: str = Field(
        validation_alias=AliasChoices("ENV", "APP_ENV"),
    )
    DEBUG: bool
    API_PREFIX: str
    API_HOST: str
    API_PORT: int
    START_PERIOD: int
    APP_VERSION: str
    LOG_DIR: str
    ALLOWED_ORIGINS: str = Field(
        validation_alias=AliasChoices("ALLOWED_ORIGINS", "CORS_ORIGINS"),
    )
    GEMINI_API_KEY: str
    GEMINI_MODEL: str
    METRICS_TOKEN: str
    URL_METADATA_ENABLED: bool = False
    URL_METADATA_TIMEOUT: float = 4.0
    URL_METADATA_CACHE_TTL: int = 3600
    URL_METADATA_CACHE_MAXSIZE: int = 2048
    URL_METADATA_MAX_CONCURRENT: int = 8
    URL_REPUTATION_ENABLED: bool = True
    URL_REPUTATION_TIMEOUT: float = 8.0
    URL_REPUTATION_CACHE_TTL: int = 1800
    URL_REPUTATION_CACHE_MAXSIZE: int = 4096
    URL_REPUTATION_MAX_CONCURRENT: int = 6
    URLHAUS_ENABLED: bool = True
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )


settings = Settings()

# Import explicitly with: from app.core.config import settings
__all__ = ["Settings", "settings"]