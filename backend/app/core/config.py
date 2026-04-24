from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Kestrel API"
    env: Literal["development", "production", "test"] = "development"
    debug: bool = True

    database_url: str = Field(
        default="postgresql+asyncpg://kestrel:kestrel@postgres:5432/kestrel"
    )
    redis_url: str = Field(default="redis://redis:6379/0")

    meili_host: str = "http://meilisearch:7700"
    meili_master_key: str = "change-me-in-production"
    meili_index: str = "vulnerabilities"

    nvd_api_key: str | None = None
    github_token: str | None = None

    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])

    # Scheduler cadence (seconds)
    nvd_interval_seconds: int = 3600
    exploit_db_interval_seconds: int = 21600
    github_advisory_interval_seconds: int = 10800

    # Retry / rate-limit defaults
    http_max_retries: int = 5
    http_base_backoff: float = 2.0

    # Sandbox (in-app vulnerability lab containers)
    sandbox_network: str = "kestrel_sandbox_net"
    sandbox_ttl_seconds: int = 1800  # 30 minutes; auto-reaped past this
    sandbox_memory_mb: int = 256
    sandbox_cpus: float = 0.5
    sandbox_pids_limit: int = 128
    sandbox_max_concurrent: int = 8
    # ``compose`` lab mode launches sibling stacks via the host docker daemon
    # (docker-out-of-docker). The compose file the daemon reads must live at
    # a path the *host* can see, which is rarely the same as the path inside
    # the backend container. ``vulhub_repo_path`` is where we git clone /
    # update the vulhub tree (inside the backend container), and
    # ``vulhub_host_path`` is the equivalent absolute path on the host that
    # we pass to ``docker compose -f``. Set them to the same value and bind
    # mount accordingly in docker-compose.yml.
    vulhub_repo_path: str = "/data/vulhub"
    vulhub_host_path: str = "/data/vulhub"
    vulhub_repo_remote: str = "https://github.com/vulhub/vulhub.git"
    sandbox_compose_project_prefix: str = "kestrel-sandbox"

    # Observability (모두 옵셔널 — 미설정 시 코드 경로 자체를 건너뜀)
    sentry_dsn: str | None = None
    sentry_traces_sample_rate: float = 0.1
    otel_enabled: bool = False
    otel_exporter_otlp_endpoint: str | None = None
    otel_service_name: str = "kestrel-backend"


@lru_cache
def get_settings() -> Settings:
    return Settings()
