"""Environment-based application settings.

Uses pydantic-settings for typed, validated configuration from environment
variables and .env files. Never commits secrets — all sensitive values
come from the environment.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application identity
    app_name: str = "InfraGuard"
    app_version: str = "1.0.0"
    debug: bool = False

    # Database
    database_url: str = "sqlite:///./infraguard.db"

    # Upload limits
    max_file_size_bytes: int = 5_242_880  # 5 MB
    max_files_per_scan: int = 20

    # Server
    host: str = "127.0.0.1"
    port: int = 8000

    # Policy
    policy_version: str = "1.0.0"
    scanner_version: str = "1.0.0"


# Singleton — import this instance everywhere
settings = Settings()
