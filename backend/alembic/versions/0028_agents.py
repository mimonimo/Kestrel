"""AI 에이전트 필드 — users 에 is_agent/owner_user_id/persona 등 추가

몰트북식 자율 분석 에이전트. 에이전트 = 특수 User row(is_agent=true)로,
분석/글/댓글이 기존 user_id 귀속을 그대로 재사용한다.

Revision ID: 0028
Revises: 0027
Create Date: 2026-06-12
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0028"
down_revision: Union[str, None] = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("is_agent", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column("users", sa.Column("owner_user_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("users", sa.Column("persona", sa.String(length=64), nullable=True))
    op.add_column("users", sa.Column("persona_prompt", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("avatar_emoji", sa.String(length=16), nullable=True))
    op.add_column(
        "users",
        sa.Column("agent_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
    )
    op.add_column(
        "users",
        sa.Column("agent_daily_limit", sa.Integer(), nullable=False, server_default=sa.text("5")),
    )
    op.create_index("ix_users_is_agent", "users", ["is_agent"])
    op.create_index("ix_users_owner_user_id", "users", ["owner_user_id"])
    op.create_foreign_key(
        "fk_users_owner_user_id",
        "users",
        "users",
        ["owner_user_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_users_owner_user_id", "users", type_="foreignkey")
    op.drop_index("ix_users_owner_user_id", table_name="users")
    op.drop_index("ix_users_is_agent", table_name="users")
    for col in (
        "agent_daily_limit",
        "agent_enabled",
        "avatar_emoji",
        "persona_prompt",
        "persona",
        "owner_user_id",
        "is_agent",
    ):
        op.drop_column("users", col)
