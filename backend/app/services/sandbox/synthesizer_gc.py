"""LRU garbage collector for AI-synthesized lab images (PR9-F).

Each successful ``synthesize`` call leaves behind:

  * a docker image tagged ``kestrel-syn-<sha>:latest`` (~150-400MB)
  * a ``cve_lab_mappings`` row pointing at it (kind=synthesized, verified)

Without housekeeping, the cache grows unbounded on long-lived deployments.
This module evicts the *least-recently-used* images until the cache is
under all three configured ceilings (total MB, image count, max age),
skipping images that are currently referenced by a running container so
we never yank an image out from under a live sandbox session.

GC is invoked opportunistically at the start of every ``synthesize()``
call and also exposed via ``POST /sandbox/synthesize/gc`` for operators
who want to trigger it directly.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import docker
from docker.errors import APIError, ImageNotFound, NotFound
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models import CveLabMapping, LabSourceKind

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class EvictedImage:
    cve_id: str
    image_tag: str
    size_mb: int
    reason: str  # "age" | "count" | "total_size" | "image_missing"


@dataclass
class GcStats:
    scanned: int = 0
    evicted: list[EvictedImage] = field(default_factory=list)
    freed_mb: int = 0
    retained_count: int = 0
    retained_total_mb: int = 0
    skipped_in_use: list[str] = field(default_factory=list)


@dataclass
class CacheEntry:
    """Read-only view of one synthesized-image cache row + its docker state."""

    cve_id: str
    image_tag: str
    lab_kind: str
    size_mb: int
    in_use: bool
    image_present: bool  # False when docker no longer has the image
    last_used_at: datetime | None
    last_verified_at: datetime | None
    created_at: datetime
    age_days: int  # days since LRU key (last_used_at or created_at)


@dataclass
class CacheReport:
    count: int
    total_mb: int
    in_use_count: int
    missing_image_count: int  # rows whose image vanished from docker
    oldest_last_used_at: datetime | None
    entries: list[CacheEntry] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Docker helpers (sync, run in a thread)
# ---------------------------------------------------------------------------


def _client() -> docker.DockerClient:
    return docker.from_env()


def _image_size_and_in_use(tag: str) -> tuple[int | None, bool]:
    """Return (size_bytes, has_running_container) for *tag*.

    ``size_bytes`` is None when the image is missing entirely (already
    deleted out from under us — we just drop the mapping in that case).
    """
    cli = _client()
    try:
        img = cli.images.get(tag)
    except (ImageNotFound, NotFound):
        return None, False
    except APIError as e:
        log.warning("syn_gc.inspect_failed", tag=tag, error=str(e))
        return None, False
    size = int(img.attrs.get("Size") or 0)
    try:
        users = cli.containers.list(filters={"ancestor": tag})
    except APIError as e:
        log.warning("syn_gc.containers_list_failed", tag=tag, error=str(e))
        users = []
    return size, len(users) > 0


def _remove_image(tag: str) -> bool:
    cli = _client()
    try:
        cli.images.remove(image=tag, force=False, noprune=False)
        return True
    except (ImageNotFound, NotFound):
        return True  # already gone — count as success
    except APIError as e:
        log.warning("syn_gc.remove_failed", tag=tag, error=str(e))
        return False


# ---------------------------------------------------------------------------
# Core GC
# ---------------------------------------------------------------------------


def _lru_key(row: CveLabMapping) -> datetime:
    """Sort key for LRU eviction.

    Rows that have never been used (``last_used_at is None``) sort as if
    used at row creation time — fresh syntheses that haven't run yet are
    preferred over genuinely cold ones, but still evictable when the
    cache is over quota.
    """
    return row.last_used_at or row.created_at


async def gc_synthesized_images(
    db: AsyncSession,
    *,
    target_total_mb: int | None = None,
    target_max_count: int | None = None,
    target_max_age_days: int | None = None,
) -> GcStats:
    """Evict synthesized images until under all three limits.

    Override params let the caller request a tighter sweep (e.g. when
    free disk is critical). Defaults come from settings.
    """
    settings = get_settings()
    max_total_mb = (
        target_total_mb
        if target_total_mb is not None
        else settings.sandbox_syn_image_max_total_mb
    )
    max_count = (
        target_max_count
        if target_max_count is not None
        else settings.sandbox_syn_image_max_count
    )
    max_age_days = (
        target_max_age_days
        if target_max_age_days is not None
        else settings.sandbox_syn_image_max_age_days
    )

    rows = (
        await db.scalars(
            select(CveLabMapping).where(
                CveLabMapping.kind == LabSourceKind.SYNTHESIZED,
                CveLabMapping.verified.is_(True),
            )
        )
    ).all()
    rows_sorted = sorted(rows, key=_lru_key)

    stats = GcStats(scanned=len(rows_sorted))
    now = datetime.now(timezone.utc)
    age_cutoff = now - timedelta(days=max_age_days) if max_age_days > 0 else None

    # Pull image sizes + in-use flags up front. The in-use status is
    # snapshotted once per sweep — a session that starts mid-sweep won't
    # protect its image, but eviction always re-checks via the docker SDK
    # which would refuse to remove an image whose containers exist (we
    # call ``remove(force=False)`` deliberately for that safety).
    async def _inspect(row: CveLabMapping) -> tuple[CveLabMapping, int | None, bool]:
        tag = str((row.spec or {}).get("image", ""))
        if not tag:
            return row, None, False
        size, in_use = await asyncio.to_thread(_image_size_and_in_use, tag)
        return row, size, in_use

    inspected = await asyncio.gather(*[_inspect(r) for r in rows_sorted])

    # (row, size_bytes, in_use) — keep in_use cached so each pass below is
    # O(rows) without extra docker round-trips.
    survivors: list[tuple[CveLabMapping, int, bool]] = []

    async def _evict(row: CveLabMapping, size_bytes: int, reason: str) -> bool:
        tag = str((row.spec or {}).get("image", ""))
        if tag and reason != "image_missing":
            ok = await asyncio.to_thread(_remove_image, tag)
            if not ok:
                log.warning("syn_gc.skip_remove_failure", tag=tag)
                return False
        await db.delete(row)
        size_mb = size_bytes // (1024 * 1024) if size_bytes else 0
        stats.evicted.append(
            EvictedImage(
                cve_id=row.cve_id,
                image_tag=tag,
                size_mb=size_mb,
                reason=reason,
            )
        )
        stats.freed_mb += size_mb
        return True

    # Pass 1: drop rows whose underlying image vanished — useless to keep.
    for row, size, in_use in inspected:
        if size is None:
            await _evict(row, 0, "image_missing")
            continue
        survivors.append((row, size, in_use))

    # Pass 2: age-based eviction.
    if age_cutoff is not None:
        kept: list[tuple[CveLabMapping, int, bool]] = []
        for row, size_bytes, in_use in survivors:
            if _lru_key(row) < age_cutoff and not in_use:
                if not await _evict(row, size_bytes, "age"):
                    kept.append((row, size_bytes, in_use))
                continue
            if in_use and _lru_key(row) < age_cutoff:
                stats.skipped_in_use.append(str((row.spec or {}).get("image", "")))
            kept.append((row, size_bytes, in_use))
        survivors = kept

    # Pass 3: count-based eviction (oldest first — already sorted).
    if max_count > 0 and len(survivors) > max_count:
        excess = len(survivors) - max_count
        kept = []
        evicted_now = 0
        for row, size_bytes, in_use in survivors:
            if evicted_now < excess and not in_use:
                if await _evict(row, size_bytes, "count"):
                    evicted_now += 1
                    continue
            elif evicted_now < excess and in_use:
                stats.skipped_in_use.append(str((row.spec or {}).get("image", "")))
            kept.append((row, size_bytes, in_use))
        survivors = kept

    # Pass 4: total-size eviction.
    if max_total_mb > 0:
        max_total_bytes = max_total_mb * 1024 * 1024
        running_total = sum(s for _, s, _ in survivors)
        if running_total > max_total_bytes:
            kept = []
            for row, size_bytes, in_use in survivors:
                if running_total > max_total_bytes and not in_use:
                    if await _evict(row, size_bytes, "total_size"):
                        running_total -= size_bytes
                        continue
                elif running_total > max_total_bytes and in_use:
                    stats.skipped_in_use.append(str((row.spec or {}).get("image", "")))
                kept.append((row, size_bytes, in_use))
            survivors = kept

    stats.retained_count = len(survivors)
    stats.retained_total_mb = sum(s for _, s, _ in survivors) // (1024 * 1024)

    if stats.evicted:
        await db.commit()
        log.info(
            "syn_gc.swept",
            evicted=len(stats.evicted),
            freed_mb=stats.freed_mb,
            retained=stats.retained_count,
            retained_mb=stats.retained_total_mb,
        )
    return stats


async def report_synthesized_cache(db: AsyncSession) -> CacheReport:
    """Inspect the synthesized-image cache without evicting anything.

    Drives the operator dashboard — same docker SDK calls as the GC sweep
    (size + ancestor-container check) but read-only. Sorted oldest-LRU
    first so the UI can show what *would* be evicted next.
    """
    rows = (
        await db.scalars(
            select(CveLabMapping).where(
                CveLabMapping.kind == LabSourceKind.SYNTHESIZED,
                CveLabMapping.verified.is_(True),
            )
        )
    ).all()
    rows_sorted = sorted(rows, key=_lru_key)
    now = datetime.now(timezone.utc)

    async def _inspect(row: CveLabMapping) -> tuple[CveLabMapping, int | None, bool]:
        tag = str((row.spec or {}).get("image", ""))
        if not tag:
            return row, None, False
        size, in_use = await asyncio.to_thread(_image_size_and_in_use, tag)
        return row, size, in_use

    inspected = await asyncio.gather(*[_inspect(r) for r in rows_sorted])

    entries: list[CacheEntry] = []
    total_bytes = 0
    in_use_count = 0
    missing_count = 0
    oldest_last_used: datetime | None = None

    for row, size, in_use in inspected:
        present = size is not None
        size_bytes = size or 0
        total_bytes += size_bytes
        if in_use:
            in_use_count += 1
        if not present:
            missing_count += 1
        lru = _lru_key(row)
        age_days = max(0, (now - lru).days) if lru else 0
        if row.last_used_at is not None:
            if oldest_last_used is None or row.last_used_at < oldest_last_used:
                oldest_last_used = row.last_used_at
        entries.append(
            CacheEntry(
                cve_id=row.cve_id,
                image_tag=str((row.spec or {}).get("image", "")),
                lab_kind=row.lab_kind,
                size_mb=size_bytes // (1024 * 1024),
                in_use=in_use,
                image_present=present,
                last_used_at=row.last_used_at,
                last_verified_at=row.last_verified_at,
                created_at=row.created_at,
                age_days=age_days,
            )
        )

    return CacheReport(
        count=len(entries),
        total_mb=total_bytes // (1024 * 1024),
        in_use_count=in_use_count,
        missing_image_count=missing_count,
        oldest_last_used_at=oldest_last_used,
        entries=entries,
    )
