"""Application configuration via environment variables."""
from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "SentinelIX"
    app_env: str = "development"
    secret_key: str = "sentinelix-dev-secret-change-me"
    access_token_expire_minutes: int = 60 * 24
    algorithm: str = "HS256"

    database_url: str = "sqlite+aiosqlite:///./sentinelix.db"

    cors_origins: str | List[str] = Field(default_factory=lambda: ["http://localhost:5173"])

    nvd_api_key: str | None = None
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_results_per_page: int = 2000
    nvd_request_delay_seconds: float = 0.6

    cisa_kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )

    shodan_api_key: str | None = None

    nvd_ingest_interval_minutes: int = 10
    nvd_daily_ingest_hour: int = 2  # UTC — NIST reduces rate limits overnight
    nvd_initial_fetch_days: int = 30
    nvd_daily_fetch_days: int = 1
    nvd_run_initial_ingest: bool = True
    kev_ingest_cron_hour: int = 0
    telemetry_cache_ttl_seconds: int = 86400

    # Frontend URL for Playwright PDF printing (React report templates).
    frontend_base_url: str = "http://localhost:5173"

    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = "https://api.openai.com/v1"

    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-4-5"

    newsapi_key: str | None = None
    news_ingest_interval_minutes: int = 10
    news_retention_hours: int = 48
    news_rss_feeds: str | List[str] = Field(
        default_factory=lambda: [
            "https://feeds.feedburner.com/TheHackersNews",
            "https://www.bleepingcomputer.com/feed/",
            "https://krebsonsecurity.com/feed/",
            "https://www.darkreading.com/rss.xml",
        ]
    )

    @field_validator("news_rss_feeds", mode="after")
    @classmethod
    def split_feeds(cls, v):
        if isinstance(v, str):
            return [f.strip() for f in v.split(",") if f.strip()]
        return v

    initial_admin_email: str = "admin@sentinelix.io"
    initial_admin_password: str = "ChangeMe!2026"
    initial_admin_username: str = "admin"

    # Optional SMTP for email OTP (leave host empty to log codes instead)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_use_tls: bool = True

    @field_validator("cors_origins", mode="after")
    @classmethod
    def split_cors(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
