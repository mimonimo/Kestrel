"""users.default_analysis_public — 분석 기록 기본 공개 설정

Revision ID: 0037
Revises: 0036
Create Date: 2026-06-15
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0037"
down_revision: Union[str, None] = "0036"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "default_analysis_public",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "default_analysis_public")
