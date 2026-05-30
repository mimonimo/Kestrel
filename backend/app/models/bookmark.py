"""Bookmark — per-user CVE 즐겨찾기.

PR 10-CN 이후로 로그인 필수. 기존 익명 즐겨찾기(client_id) 는 backward
compat 을 위해 컬럼만 남겨둠 — 신규 로우는 모두 user_id 가 채워진다.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Bookmark(Base):
    __tablename__ = "bookmarks"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # 로그인 사용자 식별 (신규).
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # 기존 익명 client_id (deprecated, backward compat 만 유지).
    client_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        # client_id 기반 unique (기존 데이터 유지)
        UniqueConstraint("client_id", "cve_id", name="uq_bookmark_client_cve"),
        # user_id 기반 unique (신규)
        UniqueConstraint("user_id", "cve_id", name="uq_bookmark_user_cve"),
        Index("ix_bookmark_client", "client_id"),
        Index("ix_bookmark_user", "user_id"),
    )
