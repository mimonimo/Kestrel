"""Shared retry policy for outbound HTTP calls to CVE sources.

Uses tenacity with exponential backoff + jitter. Retries on HTTP 429/5xx and
network errors. Permanent 4xx errors (not 429) fail fast.
"""
from __future__ import annotations

import httpx
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)


class TransientHttpError(Exception):
    """Retryable HTTP failure (5xx or 429)."""


def is_transient(exc: BaseException) -> bool:
    if isinstance(exc, (httpx.TransportError, httpx.TimeoutException, TransientHttpError)):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or 500 <= status < 600
    return False


def retrying() -> AsyncRetrying:
    settings = get_settings()
    return AsyncRetrying(
        reraise=True,
        stop=stop_after_attempt(settings.http_max_retries),
        wait=wait_exponential_jitter(initial=settings.http_base_backoff, max=60.0),
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException, TransientHttpError, httpx.HTTPStatusError)),
        before_sleep=lambda rs: log.warning(
            "http.retry",
            attempt=rs.attempt_number,
            sleep=round(rs.next_action.sleep if rs.next_action else 0, 2),
            error=str(rs.outcome.exception()) if rs.outcome else None,
        ),
    )
