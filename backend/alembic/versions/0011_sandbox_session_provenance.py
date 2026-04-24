"""sandbox session provenance — lab_source + verified columns

Revision ID: 0011
Revises: 0010
Create Date: 2026-04-24
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # lab_source_kind_enum already created in migration 0010.
    op.add_column(
        "sandbox_sessions",
        sa.Column(
            "lab_source",
            postgresql.ENUM(
                "vulhub",
                "generic",
                "synthesized",
                name="lab_source_kind_enum",
                create_type=False,
            ),
            nullable=False,
            server_default="generic",
        ),
    )
    op.add_column(
        "sandbox_sessions",
        sa.Column(
            "verified",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.create_index(
        "ix_sandbox_sessions_lab_source", "sandbox_sessions", ["lab_source"]
    )
    # lab_kind grew from 64 to 128 to fit "vendor/CVE-XXXX-YYYYY" vulhub paths.
    op.alter_column(
        "sandbox_sessions",
        "lab_kind",
        existing_type=sa.String(length=64),
        type_=sa.String(length=128),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "sandbox_sessions",
        "lab_kind",
        existing_type=sa.String(length=128),
        type_=sa.String(length=64),
        existing_nullable=False,
    )
    op.drop_index("ix_sandbox_sessions_lab_source", table_name="sandbox_sessions")
    op.drop_column("sandbox_sessions", "verified")
    op.drop_column("sandbox_sessions", "lab_source")
