"""AnalysisResult — 사용자가 실행한 AI 분석 결과를 영구 저장.

설계 (PR 10-CN):
- 로그인 필수 — ``user_id`` NOT NULL.
- 같은 CVE 를 여러 명이 분석할 수 있으므로 (cve_id, user_id) 복합 unique 는 두지 않음.
- ``visibility`` = ``public`` 이면 다른 사용자도 결과 본문을 읽을 수 있음 (커뮤니티 탭).
  ``private`` 이면 본인 외에는 메타 (제목/카테고리) 만 노출되거나 아예 안 보임.
- ``category`` — UI 에서 사용자가 고른 분석 카테고리 (general / threat-model / poc / mitigation 등).
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    category: Mapped[str] = mapped_column(String(64), nullable=False, default="general")
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    prompt_md: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_md: Mapped[str] = mapped_column(Text, nullable=False)
    # public: 모든 사용자가 본문까지 조회 가능
    # private: 본인만 조회 가능 (커뮤니티 탭에 노출되지 않음)
    visibility: Mapped[str] = mapped_column(String(16), nullable=False, default="public")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    user = relationship("User", lazy="joined")

    __table_args__ = (
        Index("ix_analysis_results_cve_created", "cve_id", "created_at"),
        Index("ix_analysis_results_user_created", "user_id", "created_at"),
        Index("ix_analysis_results_visibility_created", "visibility", "created_at"),
    )
