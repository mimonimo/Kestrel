"""Optional observability bootstrappers.

Both Sentry and OpenTelemetry packages are *optional* extras in
pyproject.toml. The init functions below silently no-op when:

  - the dependency isn't installed (``ImportError``), or
  - the relevant env var (``SENTRY_DSN`` / ``OTEL_ENABLED``) isn't set.

This keeps the default Docker image small while letting prod deployments
opt in by setting the env var + installing the extra:

    pip install -e ".[sentry]"
    pip install -e ".[otel]"
"""
from __future__ import annotations

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)


def init_sentry() -> None:
    settings = get_settings()
    if not settings.sentry_dsn:
        return
    try:
        import sentry_sdk
        from sentry_sdk.integrations.asgi import SentryAsgiMiddleware  # noqa: F401
    except ImportError:
        log.warning("sentry.skip", reason="sentry-sdk not installed")
        return

    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        traces_sample_rate=settings.sentry_traces_sample_rate,
        environment=settings.env,
        release=f"cve-watch@0.1.0",
    )
    log.info("sentry.initialized", env=settings.env)


def init_otel(app) -> None:
    """Instrument FastAPI + SQLAlchemy + httpx if otel is enabled."""
    settings = get_settings()
    if not settings.otel_enabled:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        log.warning("otel.skip", reason="opentelemetry packages not installed")
        return

    resource = Resource.create({"service.name": settings.otel_service_name})
    provider = TracerProvider(resource=resource)
    if settings.otel_exporter_otlp_endpoint:
        provider.add_span_processor(
            BatchSpanProcessor(
                OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint)
            )
        )
    trace.set_tracer_provider(provider)

    FastAPIInstrumentor.instrument_app(app)
    HTTPXClientInstrumentor().instrument()
    SQLAlchemyInstrumentor().instrument()
    log.info("otel.initialized", endpoint=settings.otel_exporter_otlp_endpoint)
