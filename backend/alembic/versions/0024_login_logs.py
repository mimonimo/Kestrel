"""users.last_login_at + login_logs 테이블 (PR 10-DE).

운영자가 "사용자 추적" 화면에서 어떤 사용자가 언제 어디에서 로그인했는지
확인하기 위한 메타. login_logs 는 최근 100개 정도만 유지하면 충분.

Revision ID: 0024
Revises: 0023
Create Date: 2026-05-31
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0024"
down_revision: Union[str, None] = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "login_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_login_logs_user_created",
        "login_logs",
        ["user_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_login_logs_user_created", table_name="login_logs")
    op.drop_table("login_logs")
    op.drop_column("users", "last_login_at")
