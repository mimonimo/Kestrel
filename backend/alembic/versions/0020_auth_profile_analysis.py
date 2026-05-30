"""Auth + Profile + AnalysisResult + user-scoped Bookmark (PR 10-CN).

스키마 변경 (단일 마이그레이션 묶음):
- ``users.nickname`` (varchar 64, nullable) — 표시명 (변경 가능, username 과 분리).
- ``users.bio`` (text, nullable) — 사용자 소개글.
- ``bookmarks.user_id`` (uuid FK users.id, nullable) — 로그인 사용자 즐겨찾기.
  기존 ``client_id`` 컬럼은 backward compat 유지 (deprecated).
- ``analysis_results`` 테이블 신규 — 사용자별 AI 분석 결과 영구 저장.

Revision ID: 0020
Revises: 0019
Create Date: 2026-05-30
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0020"
down_revision: Union[str, None] = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ─── users 프로필 필드 ──────────────────────────────
    op.add_column("users", sa.Column("nickname", sa.String(length=64), nullable=True))
    op.add_column("users", sa.Column("bio", sa.Text(), nullable=True))

    # ─── bookmarks.user_id (FK) ─────────────────────────
    op.add_column(
        "bookmarks",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_bookmark_user",
        source_table="bookmarks",
        referent_table="users",
        local_cols=["user_id"],
        remote_cols=["id"],
        ondelete="CASCADE",
    )
    # client_id 를 nullable=True 로 변경 (신규 로그인 즐겨찾기는 user_id 만 사용)
    op.alter_column(
        "bookmarks",
        "client_id",
        existing_type=sa.String(length=64),
        nullable=True,
    )
    op.create_index("ix_bookmark_user", "bookmarks", ["user_id"])
    op.create_unique_constraint(
        "uq_bookmark_user_cve", "bookmarks", ["user_id", "cve_id"]
    )

    # ─── analysis_results 신규 테이블 ───────────────────
    op.create_table(
        "analysis_results",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "category",
            sa.String(length=64),
            nullable=False,
            server_default=sa.text("'general'"),
        ),
        sa.Column("title", sa.String(length=255), nullable=True),
        sa.Column("prompt_md", sa.Text(), nullable=True),
        sa.Column("result_md", sa.Text(), nullable=False),
        sa.Column(
            "visibility",
            sa.String(length=16),
            nullable=False,
            server_default=sa.text("'public'"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_analysis_results_cve_created",
        "analysis_results",
        ["cve_id", "created_at"],
    )
    op.create_index(
        "ix_analysis_results_user_created",
        "analysis_results",
        ["user_id", "created_at"],
    )
    op.create_index(
        "ix_analysis_results_visibility_created",
        "analysis_results",
        ["visibility", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_analysis_results_visibility_created", table_name="analysis_results")
    op.drop_index("ix_analysis_results_user_created", table_name="analysis_results")
    op.drop_index("ix_analysis_results_cve_created", table_name="analysis_results")
    op.drop_table("analysis_results")

    op.drop_constraint("uq_bookmark_user_cve", "bookmarks", type_="unique")
    op.drop_index("ix_bookmark_user", table_name="bookmarks")
    op.drop_constraint("fk_bookmark_user", "bookmarks", type_="foreignkey")
    op.drop_column("bookmarks", "user_id")
    # client_id 는 그대로 둔다 (downgrade 도 backward compat 유지).

    op.drop_column("users", "bio")
    op.drop_column("users", "nickname")
