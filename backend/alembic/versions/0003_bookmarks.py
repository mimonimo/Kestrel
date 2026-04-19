"""bookmarks

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-20
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "bookmarks",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("client_id", "cve_id", name="uq_bookmark_client_cve"),
    )
    op.create_index("ix_bookmark_client", "bookmarks", ["client_id"])


def downgrade() -> None:
    op.drop_index("ix_bookmark_client", table_name="bookmarks")
    op.drop_table("bookmarks")
