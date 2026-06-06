"""UserAsset — 로그인 사용자의 자산(벤더·제품)을 서버에 영속화.

PR 10-FB: 기존 자산 매칭은 브라우저 localStorage 에 자산을 두고 매 요청
``POST /assets/match`` 바디로 보내는 클라이언트 방식이었다. 그래서 서버는
"누가 무슨 자산을 가졌는지" 몰라 새 CVE 가 들어와도 *먼저* 알림을 보낼 수
없었다. 알림(웹훅/인앱)을 위해 로그인 사용자의 자산만 DB 에 저장한다.

하이브리드: 비로그인 사용자는 종전처럼 localStorage + on-demand match 로
동작(알림 없음). 로그인 사용자는 서버 저장 → 수집 훅이 매칭 시 알림 생성.
``vendor``/``product`` 는 ILIKE 패턴(``*`` 와일드카드 포함) 그대로 보관 —
assets.py 의 ``_to_ilike`` 매칭 규칙과 동일하게 affected_products 에 매칭된다.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class UserAsset(Base):
    __tablename__ = "user_assets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    vendor: Mapped[str] = mapped_column(String(120), nullable=False)
    product: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("user_id", "vendor", "product", name="uq_user_asset"),
        Index("ix_user_asset_user", "user_id"),
    )
