"""Application configuration using Pydantic Settings."""

from functools import lru_cache
from typing import Optional
from urllib.parse import urlsplit

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_DEVELOPMENT_SECRET_KEY = "dev-secret-key-change-in-production-minimum-32-bytes-long"
_DEVELOPMENT_CORS_ORIGINS = (
    "http://localhost:3000",
    "http://127.0.0.1:8000",
)
_MINIMUM_PRODUCTION_SECRET_LENGTH = 32


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
    SECRET_KEY: str = _DEVELOPMENT_SECRET_KEY
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Browser access
    CORS_ORIGINS: Optional[str] = None

    # Storage settings
    STORAGE_DIR: str = "storage/documents"
    MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB default

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def cors_origins(self) -> list[str]:
        """Return configured origins or local development defaults."""
        if self.CORS_ORIGINS is None:
            return list(_DEVELOPMENT_CORS_ORIGINS)
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

    @model_validator(mode="after")
    def validate_deployment_settings(self) -> "Settings":
        origins = self.cors_origins
        if not origins or any(not origin for origin in origins):
            raise ValueError("CORS_ORIGINS must contain at least one origin")
        for origin in origins:
            parsed = urlsplit(origin)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or parsed.path
                or parsed.query
                or parsed.fragment
                or parsed.username
                or parsed.password
            ):
                raise ValueError(
                    "CORS_ORIGINS must be a comma-separated list of HTTP(S) origins"
                )

        if self.APP_ENV.lower() == "production":
            if self.SECRET_KEY == _DEVELOPMENT_SECRET_KEY:
                raise ValueError("SECRET_KEY must be configured for production")
            if len(self.SECRET_KEY) < _MINIMUM_PRODUCTION_SECRET_LENGTH:
                raise ValueError(
                    "SECRET_KEY must be at least 32 characters in production"
                )
            if self.CORS_ORIGINS is None:
                raise ValueError("CORS_ORIGINS must be configured for production")
            if all(
                urlsplit(origin).hostname in {"localhost", "127.0.0.1", "::1"}
                for origin in origins
            ):
                raise ValueError(
                    "Production CORS_ORIGINS must include a non-local frontend origin"
                )

        return self


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()


settings = get_settings()
