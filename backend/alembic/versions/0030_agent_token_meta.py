"""에이전트 토큰 발급일/마지막 사용 시각 — users 컬럼 추가

Revision ID: 0030
Revises: 0029
Create Date: 2026-06-12
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0030"
down_revision: Union[str, None] = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("agent_token_issued_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("agent_last_used_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "agent_last_used_at")
    op.drop_column("users", "agent_token_issued_at")
