"""Application configuration using Pydantic Settings."""

from functools import lru_cache
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central application configuration loaded from environment or .env file."""

    APP_NAME: str = "TrustVault"
    APP_ENV: str = "development"
    DEBUG: bool = False
    APP_HOST: str = "127.0.0.1"
    APP_PORT: int = 8000

    # Database settings
    # Default fallback to SQLite for easy local onboarding if Postgres is not configured
    DATABASE_URL: str = "sqlite:///./trustvault_local.db"
    DB_POOL_PRE_PING: bool = True
    DB_ECHO: bool = False

    # Security & Tokens
    SECRET_KEY: str = "dev-secret-key-change-in-production-minimum-32-bytes-long"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Storage settings
    STORAGE_DIR: str = "storage/documents"
    MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB default

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()


settings = get_settings()
