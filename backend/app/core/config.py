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
    postgres_dsn: str = os.getenv(
        "POSTGRES_DSN",
        "postgresql://sentinel:change-this-development-password@postgres:5432/sentinel_copilot",
    )
    detector_poll_interval_seconds: float = float(os.getenv("DETECTOR_POLL_INTERVAL_SECONDS", "10"))
    detector_batch_size: int = int(os.getenv("DETECTOR_BATCH_SIZE", "100"))


settings = Settings()
