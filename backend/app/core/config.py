from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str
    APP_ENV: str
    DEBUG: bool = True
    API_PREFIX: str
    API_PORT: int
    START_PERIOD: int
    APP_VERSION: str


    LOG_DIR: str

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )


settings = Settings()

# Import explicitly with: from app.core.config import settings
__all__ = ["Settings", "settings"]