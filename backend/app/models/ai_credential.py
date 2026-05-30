from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AiCredential(Base):
    __tablename__ = "ai_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # 사용자별 분리 (PR 10-CP2). nullable=True 로 두는 이유:
    # 1) PR 10-CP2 이전에 만들어진 단일 시스템 credential 들의 backward compat,
    # 2) 일반 사용자가 등록하지 못한 일부 운영용 credential (관리자 전용) 보존.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    label: Mapped[str] = mapped_column(String(64), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(64), nullable=False)
    api_key: Mapped[str] = mapped_column(Text, nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # per-user active flag — AppSettings 의 단일 active_credential_id 대신
    # 사용자별로 본인 active credential 을 따로 지정.
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
