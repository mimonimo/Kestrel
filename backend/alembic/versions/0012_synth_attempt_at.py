"""cve_lab_mappings.last_synthesis_attempt_at — rate-limit AI synthesis retries

Revision ID: 0012
Revises: 0011
Create Date: 2026-04-25
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "cve_lab_mappings",
        sa.Column(
            "last_synthesis_attempt_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("cve_lab_mappings", "last_synthesis_attempt_at")
