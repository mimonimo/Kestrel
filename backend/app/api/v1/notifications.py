"""알림 API — 인앱 알림 피드 + 외부 채널(Slack/Discord 웹훅) 관리.

PR 10-FB. 알림 자체는 수집 훅(services.notifications.notify_new_cves)이 생성한다.
여기서는 조회·읽음 처리·채널 CRUD·테스트 발송만 담당. 모두 로그인 필수.
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field, field_validator
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_user
from app.core.database import get_db
from app.models import Notification, NotificationChannel, User
from app.models.notification import CHANNEL_KINDS
from app.schemas.vulnerability import CamelModel
from app.services.notifications import _dispatch_webhook, _format_message

router = APIRouter(prefix="/notifications", tags=["notifications"])


# ── 인앱 알림 ────────────────────────────────────────────────
class NotificationItem(CamelModel):
    id: int
    cve_id: str
    vendor: str | None
    product: str | None
    severity: str | None
    title: str | None
    read: bool
    created_at: datetime


class NotificationsResponse(CamelModel):
    items: list[NotificationItem]
    unread_count: int


@router.get("", response_model=NotificationsResponse, response_model_by_alias=True)
async def list_notifications(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
) -> NotificationsResponse:
    rows = (
        await db.execute(
            select(Notification)
            .where(Notification.user_id == user.id)
            .order_by(Notification.created_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    unread = (
        await db.execute(
            select(func.count())
            .select_from(Notification)
            .where(Notification.user_id == user.id, Notification.read_at.is_(None))
        )
    ).scalar_one()
    return NotificationsResponse(
        items=[
            NotificationItem(
                id=n.id,
                cve_id=n.cve_id,
                vendor=n.vendor,
                product=n.product,
                severity=n.severity,
                title=n.title,
                read=n.read_at is not None,
                created_at=n.created_at,
            )
            for n in rows
        ],
        unread_count=int(unread or 0),
    )


class MarkReadRequest(CamelModel):
    # None/빈 목록 = 전체 읽음. 특정 id 목록을 주면 그것만.
    ids: list[int] | None = None


@router.post("/read")
async def mark_read(
    req: MarkReadRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    now = datetime.now(timezone.utc)
    stmt = (
        update(Notification)
        .where(Notification.user_id == user.id, Notification.read_at.is_(None))
        .values(read_at=now)
    )
    if req.ids:
        stmt = stmt.where(Notification.id.in_(req.ids))
    result = await db.execute(stmt)
    await db.commit()
    return {"marked": result.rowcount or 0}


# ── 외부 채널 (Slack/Discord 웹훅) ───────────────────────────
class ChannelItem(CamelModel):
    id: int
    kind: str
    url: str
    enabled: bool
    created_at: datetime


class ChannelCreate(CamelModel):
    kind: str
    url: str = Field(min_length=8, max_length=500)

    @field_validator("kind")
    @classmethod
    def _kind_ok(cls, v: str) -> str:
        if v not in CHANNEL_KINDS:
            raise ValueError(f"kind must be one of {CHANNEL_KINDS}")
        return v

    @field_validator("url")
    @classmethod
    def _url_ok(cls, v: str) -> str:
        if not v.startswith("https://"):
            raise ValueError("웹훅 URL 은 https:// 여야 합니다")
        return v


def _mask(url: str) -> str:
    """웹훅 URL 의 토큰 부분을 가려 응답에 노출하지 않는다."""
    if len(url) <= 24:
        return url[:8] + "…"
    return url[:24] + "…" + url[-4:]


@router.get("/channels", response_model=list[ChannelItem], response_model_by_alias=True)
async def list_channels(
    user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
) -> list[ChannelItem]:
    rows = (
        await db.execute(
            select(NotificationChannel)
            .where(NotificationChannel.user_id == user.id)
            .order_by(NotificationChannel.created_at.desc())
        )
    ).scalars().all()
    return [
        ChannelItem(
            id=c.id, kind=c.kind, url=_mask(c.url), enabled=c.enabled, created_at=c.created_at
        )
        for c in rows
    ]


@router.post("/channels", response_model=ChannelItem, response_model_by_alias=True)
async def create_channel(
    req: ChannelCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ChannelItem:
    ch = NotificationChannel(user_id=user.id, kind=req.kind, url=req.url, enabled=True)
    db.add(ch)
    await db.commit()
    await db.refresh(ch)
    return ChannelItem(
        id=ch.id, kind=ch.kind, url=_mask(ch.url), enabled=ch.enabled, created_at=ch.created_at
    )


@router.delete("/channels/{channel_id}")
async def delete_channel(
    channel_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(
        delete(NotificationChannel).where(
            NotificationChannel.id == channel_id,
            NotificationChannel.user_id == user.id,
        )
    )
    await db.commit()
    if not result.rowcount:
        raise HTTPException(status_code=404, detail="채널을 찾을 수 없습니다.")
    return {"deleted": True}


@router.post("/channels/{channel_id}/test")
async def test_channel(
    channel_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    ch = await db.scalar(
        select(NotificationChannel).where(
            NotificationChannel.id == channel_id,
            NotificationChannel.user_id == user.id,
        )
    )
    if ch is None:
        raise HTTPException(status_code=404, detail="채널을 찾을 수 없습니다.")
    msg = _format_message(
        "CVE-0000-0000", "HIGH", "example", "product",
        "Kestrel 알림 테스트 — 이 메시지가 보이면 채널이 정상입니다.",
    )
    async with httpx.AsyncClient() as client:
        await _dispatch_webhook(client, ch.kind, ch.url, msg)
    return {"sent": True}
