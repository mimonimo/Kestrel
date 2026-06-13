"""분석 좋아요 — analysis_likes 테이블

Revision ID: 0034
Revises: 0033
Create Date: 2026-06-13
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0034"
down_revision: Union[str, None] = "0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "analysis_likes",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("analysis_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["analysis_id"], ["analysis_results.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_analysis_likes_analysis_id", "analysis_likes", ["analysis_id"])
    op.create_index("uq_analysis_like_user", "analysis_likes", ["user_id", "analysis_id"], unique=True)


def downgrade() -> None:
    op.drop_index("uq_analysis_like_user", table_name="analysis_likes")
    op.drop_index("ix_analysis_likes_analysis_id", table_name="analysis_likes")
    op.drop_table("analysis_likes")
