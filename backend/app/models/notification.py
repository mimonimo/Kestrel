"""알림 — 자산 매칭 시 사용자에게 전달.

PR 10-FB. 두 축:
- ``Notification``: 인앱 알림 피드 1행 = "내 자산 X 에 새 CVE Y 가 떴다". 항상 생성
  (인앱은 기본 on). 읽음 처리는 ``read_at`` 으로.
- ``NotificationChannel``: 외부 전달 채널(Slack/Discord 수신 웹훅 URL). 로그인
  사용자가 등록하면 매칭 시 인앱 + 해당 웹훅으로도 POST.

수집 파이프라인이 새/갱신 CVE 의 affected_products 를 user_assets 와 매칭해
이 두 테이블을 채운다(전체 백필 시엔 스킵 — 신규 유입만 알림).
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

# 채널 종류 — PG enum 대신 String 으로 두어 마이그레이션을 단순화.
CHANNEL_KINDS = ("slack", "discord")


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # 'slack' | 'discord' — 둘 다 incoming-webhook POST 라 페이로드만 다르다.
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (Index("ix_notif_channel_user", "user_id"),)


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    # 어떤 자산이 매칭됐는지 (벤더/제품) — 알림 문구에 표시.
    vendor: Mapped[str | None] = mapped_column(String(120), nullable=True)
    product: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # 알림 생성 시점의 severity 스냅샷(나중에 바뀌어도 알림은 당시 기준).
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    title: Mapped[str | None] = mapped_column(String(300), nullable=True)
    read_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        # 같은 사용자에게 같은 CVE×제품 알림 중복 방지 (재갱신 시 재알림 안 함).
        Index(
            "uq_notif_user_cve_product",
            "user_id",
            "cve_id",
            "product",
            unique=True,
        ),
        Index("ix_notif_user_created", "user_id", "created_at"),
        Index("ix_notif_user_unread", "user_id", "read_at"),
    )
