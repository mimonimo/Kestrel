from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEFAULT_JWT_SECRET = "dev-only-change-me-in-production-please-32chars-min"


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

    # ─── Auth / 세션 ─────────────────────────────────────
    # JWT_SECRET 은 반드시 환경변수에서. 코드/리포에 절대 하드코딩 X.
    # 길이 32+ 권장 (HS256). 운영은 AWS Secrets Manager 에서 주입.
    jwt_secret: str = _DEFAULT_JWT_SECRET
    jwt_exp_hours: int = 12
    # 가입 시 이 이메일이면 자동으로 role=ADMIN 부여 (콤마 분리).
    # 예: "owner@example.com,ops@example.com"
    initial_admin_emails: str = ""

    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])

    # ─── 이메일 (회원가입 인증 / 비밀번호 재설정) ─────────────
    # email_enabled=false 면 실제 발송 대신 백엔드 로그로 링크를 출력하는
    # "콘솔 모드" — 로컬 개발/테스트에서 SES 자격증명 없이 흐름을 검증할 수 있다.
    # 운영(SES)에서는 user_data 가 EMAIL_ENABLED=true 로 주입.
    email_enabled: bool = False
    # 발송 백엔드 — "ses"(기본) 또는 "smtp"(Resend 등 외부 SMTP).
    # SES 샌드박스 해제 거절 대비, smtp 로 외부 트랜잭션 메일 서비스 사용 가능.
    email_provider: str = "ses"
    # 발신 주소 — SES/SMTP 에서 검증된 도메인/주소여야 한다.
    email_from: str = "no-reply@kestrel.forum"
    email_from_name: str = "Kestrel"
    # ── SMTP(provider=smtp) 설정 — 예: Resend(smtp.resend.com:465, user=resend, pass=API키) ──
    smtp_host: str = ""
    smtp_port: int = 465
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_ssl: bool = True       # 465=SSL(True) / 587=STARTTLS(False)
    # SES 리전 (서울 ap-northeast-2 에서 SES 사용 가능). boto3 가 인스턴스
    # IAM 역할 자격증명을 자동 사용 — 정적 키 불필요.
    aws_region: str = "ap-northeast-2"
    # 운영 알림(사용자 신고 등)을 발행할 SNS 토픽 ARN. 비우면 발행 비활성(no-op).
    alerts_sns_topic_arn: str | None = None
    # 이메일 링크에 쓰는 공개 베이스 URL. 비우면 cors_origins[0] 로 폴백.
    # 운영은 https://www.kestrel.forum.
    public_base_url: str = ""
    # 토큰 만료 — 가입 인증 메일 링크 24h, 비밀번호 재설정 링크 1h.
    email_verify_token_ttl_hours: int = 24
    password_reset_token_ttl_minutes: int = 60

    # 멀티 컨테이너 분리 (PR 10-CN, AWS ECS).
    # ``true`` 일 때만 lifespan 에서 APScheduler 가 가동.
    # ECS 구성: api 태스크(다수, Spot) = false, scheduler 태스크(1개, On-Demand) = true.
    # 로컬 docker-compose 는 단일 backend 컨테이너라 기본 true.
    kestrel_run_scheduler: bool = True

    # Scheduler cadence (seconds) — 실시간 근접 수집. delta 는 가벼우니 자주 돌려도
    # 부하/레이트리밋 여유가 있다(NVD 키 50req/30s, GHSA 5000pts/h). ExploitDB 만
    # 매 실행이 CSV 전체(~수십MB) 재다운로드라 1h 로 둔다(EDB 발행량 자체가 저빈도).
    nvd_interval_seconds: int = 600  # 10분
    exploit_db_interval_seconds: int = 3600  # 1시간
    github_advisory_interval_seconds: int = 900  # 15분

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
    # ---- MITRE cvelistV5 bulk source (PR 10-AF) ---------------------
    # The official CVE Program canonical store — every published CVE as
    # one JSON file under cves/{year}/{thousand}xxx/. Cloned once,
    # pulled daily for delta. Covers ~340k records vs NVD's ~95k slice
    # in our DB.
    mitre_repo_path: str = "/data/mitre_cvelist"
    mitre_repo_remote: str = "https://github.com/CVEProject/cvelistV5.git"
    mitre_interval_seconds: int = 1800  # 30분 — git pull delta 라 가벼움
    # ---- AI 에이전트 자동 분석 (몰트북식) ---------------------------
    agents_enabled: bool = True
    agents_interval_minutes: int = 30  # 에이전트 자동 분석 사이클 주기
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

    @model_validator(mode="after")
    def _enforce_prod_hardening(self) -> "Settings":
        # 프로덕션에서 기본(공개) JWT 시크릿으로 기동하면 누구나 토큰을 위조할 수
        # 있으므로 fail-closed. 마찬가지로 prod 에서 debug 가 켜져 있으면 끈다.
        if self.env == "production":
            if self.jwt_secret == _DEFAULT_JWT_SECRET or len(self.jwt_secret) < 32:
                raise ValueError(
                    "JWT_SECRET must be set to a strong (32+ char) value in production"
                )
            object.__setattr__(self, "debug", False)
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
