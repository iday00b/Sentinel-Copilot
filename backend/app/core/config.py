"""Runtime settings for the backend."""

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    """Minimal environment-backed application settings."""

    app_name: str = os.getenv("APP_NAME", "Sentinel Copilot")
    app_environment: str = os.getenv("APP_ENV", "development")
    app_version: str = os.getenv("APP_VERSION", "0.1.0")
    elasticsearch_url: str = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
    elasticsearch_timeout_seconds: float = float(os.getenv("ELASTICSEARCH_TIMEOUT_SECONDS", "5"))


settings = Settings()
