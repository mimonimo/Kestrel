"""AuditLog — 보안/운영 감사 이벤트 기록 (PR 10-DX).

login_logs 가 "성공 로그인" 시점만 담는 데 비해, audit_logs 는 보안상 의미 있는
사건 전반을 남긴다: 로그인 성공/실패, 가입, 비밀번호 변경, (관리자) 역할 변경·
사용자 삭제·외부 키 변경 등. 운영자 감사 화면에서 시간 역순으로 조회.

설계:
- ``actor_user_id`` 는 SET NULL — 행위자가 삭제돼도 감사 기록은 남는다.
- ``actor_label`` 에 이메일/사용자명 스냅샷을 박아, 사용자 삭제 후에도 누가 했는지
  식별 가능.
- ``action`` 은 'login.success' 같은 점-구분 문자열(상수는 app.core.audit).
- 민감정보(비밀번호·토큰)는 절대 기록하지 않는다.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    actor_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detail: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
