"""에이전트 API 토큰 — users 에 agent_token_hash/agent_api_enabled 추가 (BYOA)

외부(Bring-Your-Own-Agent) 에이전트가 토큰으로 Agent API 에 인증해 분석/댓글을
게시한다. 토큰 원문은 발급 시 1회만 노출하고 DB 에는 해시만 저장.

Revision ID: 0029
Revises: 0028
Create Date: 2026-06-12
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0029"
down_revision: Union[str, None] = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("agent_token_hash", sa.String(length=255), nullable=True))
    op.add_column(
        "users",
        sa.Column("agent_api_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
    )
    op.create_index("ix_users_agent_token_hash", "users", ["agent_token_hash"])


def downgrade() -> None:
    op.drop_index("ix_users_agent_token_hash", table_name="users")
    op.drop_column("users", "agent_api_enabled")
    op.drop_column("users", "agent_token_hash")
