"""ai_credentials.user_id FK + per-user is_active (PR 10-CP2).

일반 사용자도 자기 Claude 자격증명을 등록·활성화할 수 있도록 user-scoped 화.

- ``ai_credentials.user_id`` (uuid FK, nullable) — 로그인 사용자의 자격증명.
  NULL 인 row 는 PR 10-CP2 이전에 만들어진 시스템 단일 credential (운영용).
- ``ai_credentials.is_active`` (bool, default false) — 본인 active 표식.
  AppSettings.active_credential_id 는 호환을 위해 컬럼만 남겨 두되 더 이상
  application 에서 source-of-truth 로 사용하지 않음.

Revision ID: 0021
Revises: 0020
Create Date: 2026-05-30
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0021"
down_revision: Union[str, None] = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ai_credentials",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_ai_credential_user",
        source_table="ai_credentials",
        referent_table="users",
        local_cols=["user_id"],
        remote_cols=["id"],
        ondelete="CASCADE",
    )
    op.create_index(
        "ix_ai_credential_user", "ai_credentials", ["user_id"]
    )
    op.add_column(
        "ai_credentials",
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    # 기존 단일 시스템 active credential 이 있다면 그대로 is_active=true 로 마킹.
    # PR 10-CP2 이전 active_credential_id 가 가리키던 row 만 대상.
    op.execute(
        """
        UPDATE ai_credentials
           SET is_active = true
         WHERE id = (SELECT active_credential_id FROM app_settings WHERE id = 1)
        """
    )


def downgrade() -> None:
    op.drop_column("ai_credentials", "is_active")
    op.drop_index("ix_ai_credential_user", table_name="ai_credentials")
    op.drop_constraint("fk_ai_credential_user", "ai_credentials", type_="foreignkey")
    op.drop_column("ai_credentials", "user_id")
