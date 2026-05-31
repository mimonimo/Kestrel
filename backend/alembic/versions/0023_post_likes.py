"""posts.like_count + post_likes 테이블 (PR 10-DB).

게시글 좋아요 — denormalized 카운트는 빠른 표시용, post_likes 가 source.

Revision ID: 0023
Revises: 0022
Create Date: 2026-05-31
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0023"
down_revision: Union[str, None] = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "posts",
        sa.Column(
            "like_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.create_table(
        "post_likes",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "post_id",
            sa.Integer(),
            sa.ForeignKey("posts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_post_likes_post", "post_likes", ["post_id"])
    op.create_index(
        "uq_post_like_user_post",
        "post_likes",
        ["user_id", "post_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_post_like_user_post", table_name="post_likes")
    op.drop_index("ix_post_likes_post", table_name="post_likes")
    op.drop_table("post_likes")
    op.drop_column("posts", "like_count")
