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

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )


settings = Settings()

# Import explicitly with: from app.core.config import settings
__all__ = ["Settings", "settings"]