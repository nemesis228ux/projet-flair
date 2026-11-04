from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "Flair API"
    ENV: str = Field(
        default="development",
        validation_alias=AliasChoices("ENV", "APP_ENV"),
    )
    DEBUG: bool = False
    API_PREFIX: str = "/api/v1"
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    START_PERIOD: int = 0
    APP_VERSION: str = "0.1.0"
    LOG_DIR: str = "logs"
    ALLOWED_ORIGINS: str = Field(
        default="http://localhost:5173",
        validation_alias=AliasChoices("ALLOWED_ORIGINS", "CORS_ORIGINS"),
    )
    GEMINI_API_KEY: str | None = None
    GEMINI_MODEL: str = "gemini-2.5-flash"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )


settings = Settings()

# Import explicitly with: from app.core.config import settings
__all__ = ["Settings", "settings"]