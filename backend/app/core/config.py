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
    # ---- Sandbox isolation hardening (PR9-C, opt-in) -----------------
    # When ``sandbox_harden`` is true, image-mode containers run with
    # ``read_only=True`` and compose stacks are launched through an
    # auto-generated override file that adds the same posture to every
    # service. Both modes also pass ``runtime`` and seccomp through when
    # set. All defaults below preserve the pre-9-C behavior.
    sandbox_harden: bool = False
    # e.g. "runsc" when gVisor is installed daemon-side. ``None`` falls
    # through to the daemon's default runtime (runc).
    sandbox_runtime: str | None = None
    # Absolute path to a docker seccomp profile JSON readable by both the
    # backend container *and* the host docker daemon. Empty/None means
    # use the daemon's default profile.
    sandbox_seccomp_path: str | None = None
    # Where the per-session compose override files are written. Defaults
    # to a subdirectory of the vulhub repo so the existing bind mount makes
    # the file visible to both the backend container and the host docker
    # daemon at the same path. Override only if you know what you're doing.
    sandbox_override_dir: str = ""  # empty → resolved to <vulhub_repo_path>/.kestrel-overrides

    # ---- AI lab synthesizer (PR9-D) ----------------------------------
    # The synthesizer asks the configured LLM to produce a CVE-specific
    # reproducer (Dockerfile + app code + injection point + success
    # indicator), builds it into a docker image, runs it once to verify
    # the synthesized payload actually triggers, and only on success
    # caches the mapping. All defaults below keep the feature opt-in.
    sandbox_syn_image_prefix: str = "kestrel-syn"
    sandbox_syn_build_dir: str = ""  # empty → /tmp/kestrel-syn-builds
    sandbox_syn_build_timeout_seconds: int = 240
    sandbox_syn_verify_timeout_seconds: int = 60
    sandbox_syn_max_attempts: int = 1
    # ---- Synthesized image GC (PR9-F) --------------------------------
    # Each AI-synthesized image is ~150-400MB (slim base + python/node
    # runtime). On a multi-week deployment the cache grows unbounded
    # otherwise. The GC runs opportunistically at every synthesize() call
    # and is also exposed via POST /sandbox/synthesize/gc for manual
    # cleanup. Eviction is LRU on (last_used_at NULLS FIRST, created_at)
    # and skips images currently referenced by running containers.
    sandbox_syn_image_max_total_mb: int = 4096  # ~4GB ceiling
    sandbox_syn_image_max_count: int = 50
    sandbox_syn_image_max_age_days: int = 30

    # Observability (모두 옵셔널 — 미설정 시 코드 경로 자체를 건너뜀)
    sentry_dsn: str | None = None
    sentry_traces_sample_rate: float = 0.1
    otel_enabled: bool = False
    otel_exporter_otlp_endpoint: str | None = None
    otel_service_name: str = "kestrel-backend"


@lru_cache
def get_settings() -> Settings:
    return Settings()
