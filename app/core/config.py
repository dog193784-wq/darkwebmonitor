"""Centralized application configuration.

This module uses ``pydantic-settings`` to provide strongly-typed, environment-driven
configuration that can be shared across FastAPI routes, services, task workers,
and database initialization code.

Why this matters for privacy-aware security systems:
- Operational secrets (database credentials, SMTP secrets, Redis URLs) remain in
  environment variables instead of source code.
- Security controls (e.g., HIBP endpoint and cache TTL) can be tuned without
  changing application logic, which supports reproducibility for academic work.
"""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables.

    All values have safe development defaults and can be overridden via
    environment variables or a local ``.env`` file.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "Privacy-Aware Credential Exposure Monitoring System"
    app_env: str = "development"
    debug: bool = True

    database_url: str = Field(
        default="postgresql+psycopg://postgres:postgres@localhost:5432/darkwebmonitor",
        description="PostgreSQL DSN for SQLModel engine initialization.",
    )

    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis URL used for cache access and Celery broker/backend.",
    )

    smtp_host: str = "smtp.example.com"
    smtp_port: int = 587
    smtp_username: str = "noreply@example.com"
    smtp_password: str = "change-me"
    smtp_from_email: str = "noreply@example.com"
    smtp_use_tls: bool = True

    hibp_base_url: str = "https://api.pwnedpasswords.com"
    hibp_timeout_seconds: float = 10.0
    hibp_cache_ttl_seconds: int = 60 * 60 * 24


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a singleton settings object for dependency injection.

    ``lru_cache`` ensures settings are instantiated once per process,
    minimizing overhead and avoiding configuration drift during runtime.
    """

    return Settings()
