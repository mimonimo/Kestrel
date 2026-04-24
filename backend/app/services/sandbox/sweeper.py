"""Reaper that finds expired sandbox sessions in the DB and stops their labs.

The label-based ``manager.reap_expired`` is great for image-mode containers
because docker SDK lets us stamp ``kestrel.sandbox.expires_at`` at create
time. Compose-mode labs are different: ``docker compose up`` owns the labels
on the resulting containers, and ``docker container update`` does not let us
add labels post-hoc on most engines. So for compose labs we instead consult
the DB row, which already records ``expires_at``.

Calling both reapers from the API endpoint covers both cases without forcing
a label-update path that may not exist on the host docker version.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.sandbox import SandboxSession, SandboxStatus
from app.services.sandbox.manager import stop_lab

log = get_logger(__name__)


async def reap_expired_sessions(db: AsyncSession) -> int:
    """Stop every RUNNING sandbox session past its TTL and mark it EXPIRED.

    Returns the count of sessions reaped. Called opportunistically alongside
    ``manager.reap_expired`` from the create-session endpoint.
    """
    now = datetime.now(timezone.utc)
    rows = (
        await db.scalars(
            select(SandboxSession).where(
                SandboxSession.status == SandboxStatus.RUNNING,
                SandboxSession.expires_at.is_not(None),
                SandboxSession.expires_at <= now,
            )
        )
    ).all()

    reaped = 0
    for row in rows:
        # ``container_id`` is the manager-side handle (project name for
        # compose, container name for image mode). Falls back to the
        # container_name if the row predates the dual-handle convention.
        handle = row.container_id or row.container_name
        if not handle:
            row.status = SandboxStatus.EXPIRED
            continue
        try:
            await stop_lab(handle)
        except Exception as e:  # noqa: BLE001 — best-effort sweep
            log.warning(
                "sandbox.sweeper.stop_failed",
                session_id=str(row.id),
                handle=handle,
                error=str(e),
            )
            continue
        row.status = SandboxStatus.EXPIRED
        reaped += 1

    if reaped:
        await db.flush()
        log.info("sandbox.sweeper.reaped", count=reaped)
    return reaped
