"""Community schema — stubs for future feature (boards, comments, votes).

Tables are declared now so migrations carry them forward; endpoints will land
in a later iteration. Designed with NULLABLE FK to `vulnerabilities` so posts
and comments can attach to a CVE or stand alone.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin
from app.models.vulnerability import _pg_enum


class UserRole(str, enum.Enum):
    USER = "user"
    EXPERT = "expert"
    ADMIN = "admin"


class VoteTarget(str, enum.Enum):
    POST = "post"
    COMMENT = "comment"
    VULNERABILITY = "vulnerability"


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(_pg_enum(UserRole, "user_role_enum"), default=UserRole.USER)
    # 표시명 (nickname) + 소개글 (bio) — 프로필 편집 (PR 10-CN).
    # username 은 시스템 식별자 (변경 불가), nickname 은 표시명 (변경 가능).
    nickname: Mapped[str | None] = mapped_column(String(64), nullable=True)
    bio: Mapped[str | None] = mapped_column(Text, nullable=True)
    # PR 10-DE — 마지막 로그인 시각. auth.login 에서 갱신.
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # 이메일 인증 — 가입 시 false, 메일 링크 검증 시 true. 인증 전 로그인 차단.
    email_verified: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false"), default=False
    )
    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # ─── AI 에이전트 (몰트북식 자율 분석/토론 봇) ───────────────
    # is_agent=true 인 User 는 사람 대신 자동으로 분석·게시·댓글을 수행하는 봇.
    # owner_user_id = 이 에이전트를 만든 실제 사용자(책임 귀속 + 분석 크레딧 출처).
    # persona = 표시용 역할명, persona_prompt = 분석/댓글 시스템 프롬프트 prepend.
    is_agent: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false"), default=False, index=True
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    persona: Mapped[str | None] = mapped_column(String(64), nullable=True)
    persona_prompt: Mapped[str | None] = mapped_column(Text, nullable=True)
    avatar_emoji: Mapped[str | None] = mapped_column(String(16), nullable=True)
    agent_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true"), default=True
    )
    agent_daily_limit: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("5"), default=5
    )
    # 외부(BYOA) 에이전트 API 토큰(해시 저장) — 외부 프로그램이 Bearer 로 인증.
    agent_token_hash: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    agent_api_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true"), default=True
    )


class Post(Base, TimestampMixin):
    __tablename__ = "posts"

    id: Mapped[int] = mapped_column(primary_key=True)
    vulnerability_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    client_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    author_name: Mapped[str] = mapped_column(String(64), nullable=False, default="익명")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    view_count: Mapped[int] = mapped_column(default=0)
    # PR 10-DB — 좋아요 denormalized 카운트 + post_likes 가 source of truth.
    like_count: Mapped[int] = mapped_column(default=0, server_default="0")

    comments: Mapped[list[Comment]] = relationship(back_populates="post", cascade="all, delete-orphan")


class PostLike(Base):
    __tablename__ = "post_likes"
    __table_args__ = (
        Index("uq_post_like_user_post", "user_id", "post_id", unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    post_id: Mapped[int] = mapped_column(
        ForeignKey("posts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )


class Comment(Base, TimestampMixin):
    __tablename__ = "comments"

    id: Mapped[int] = mapped_column(primary_key=True)
    post_id: Mapped[int | None] = mapped_column(
        ForeignKey("posts.id", ondelete="CASCADE"), nullable=True, index=True
    )
    vulnerability_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    client_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    author_name: Mapped[str] = mapped_column(String(64), nullable=False, default="익명")
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("comments.id", ondelete="CASCADE"))
    content: Mapped[str] = mapped_column(Text, nullable=False)

    post: Mapped[Post | None] = relationship(back_populates="comments")


class Vote(Base):
    __tablename__ = "votes"
    __table_args__ = (
        Index("ix_vote_target", "target_type", "target_id"),
        Index("ix_vote_user_target", "user_id", "target_type", "target_id", unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    target_type: Mapped[VoteTarget] = mapped_column(_pg_enum(VoteTarget, "vote_target_enum"))
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)
    vote_type: Mapped[int] = mapped_column(default=1)  # 1 up / -1 down
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
