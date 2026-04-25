"""cve_lab_mappings.last_used_at — drives LRU eviction in synthesizer GC

Revision ID: 0013
Revises: 0012
Create Date: 2026-04-25
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "cve_lab_mappings",
        sa.Column(
            "last_used_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("cve_lab_mappings", "last_used_at")
