from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.core.observability import init_otel, init_sentry
from app.core.redis_client import close_redis
from app.scheduler.jobs import build_scheduler
from app.scripts.seed import seed_if_empty
from app.services.search_service import ensure_index

settings = get_settings()
configure_logging(debug=settings.debug)
log = get_logger(__name__)

init_sentry()


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("app.starting", env=settings.env)

    # Meilisearch index setup
    try:
        ensure_index()
    except Exception:
        log.warning("meili.ensure_failed_startup", message="index setup deferred")

    # Seed the DB so the dashboard has content on first boot.
    try:
        await seed_if_empty()
    except Exception:
        log.exception("seed.failed_startup")

    # Scheduler
    scheduler = build_scheduler()
    scheduler.start()
    app.state.scheduler = scheduler

    try:
        yield
    finally:
        log.info("app.shutting_down")
        scheduler.shutdown(wait=False)
        await close_redis()


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="실시간 CVE 및 제로데이 취약점 집약 API",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    allow_credentials=True,
)

app.include_router(api_router)

init_otel(app)


@app.get("/")
async def root() -> dict:
    return {
        "name": settings.app_name,
        "version": "0.1.0",
        "docs": "/docs",
        "api": "/api/v1",
    }
