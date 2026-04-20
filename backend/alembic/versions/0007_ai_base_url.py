"""ai base url

Revision ID: 0007
Revises: 0006
Create Date: 2026-04-20
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column("ai_base_url", sa.String(length=256), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("app_settings", "ai_base_url")
