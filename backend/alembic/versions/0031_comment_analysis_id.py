"""분석 기록별 댓글 — comments.analysis_id 추가

Revision ID: 0031
Revises: 0030
Create Date: 2026-06-13
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0031"
down_revision: Union[str, None] = "0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "comments",
        sa.Column("analysis_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_index("ix_comments_analysis_id", "comments", ["analysis_id"])
    op.create_foreign_key(
        "fk_comments_analysis_id",
        "comments",
        "analysis_results",
        ["analysis_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint("fk_comments_analysis_id", "comments", type_="foreignkey")
    op.drop_index("ix_comments_analysis_id", table_name="comments")
    op.drop_column("comments", "analysis_id")
