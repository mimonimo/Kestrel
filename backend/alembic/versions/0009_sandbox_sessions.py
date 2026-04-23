"""sandbox sessions

Revision ID: 0009
Revises: 0008
Create Date: 2026-04-24
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "DO $$ BEGIN "
        "CREATE TYPE sandbox_status_enum AS ENUM "
        "('pending', 'running', 'stopped', 'expired', 'failed'); "
        "EXCEPTION WHEN duplicate_object THEN null; END $$;"
    )
    op.create_table(
        "sandbox_sessions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
        ),
        sa.Column(
            "vulnerability_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("lab_kind", sa.String(length=64), nullable=False),
        sa.Column("container_id", sa.String(length=64), nullable=True),
        sa.Column("container_name", sa.String(length=128), nullable=True),
        sa.Column("target_url", sa.String(length=256), nullable=True),
        sa.Column(
            "status",
            postgresql.ENUM(
                "pending",
                "running",
                "stopped",
                "expired",
                "failed",
                name="sandbox_status_enum",
                create_type=False,
            ),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("last_run", postgresql.JSONB(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_sandbox_sessions_vulnerability_id",
        "sandbox_sessions",
        ["vulnerability_id"],
    )
    op.create_index("ix_sandbox_sessions_lab_kind", "sandbox_sessions", ["lab_kind"])
    op.create_index("ix_sandbox_sessions_status", "sandbox_sessions", ["status"])
    op.create_index(
        "ix_sandbox_sessions_expires_at", "sandbox_sessions", ["expires_at"]
    )
    op.create_index(
        "ix_sandbox_status_expires",
        "sandbox_sessions",
        ["status", "expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_sandbox_status_expires", table_name="sandbox_sessions")
    op.drop_index("ix_sandbox_sessions_expires_at", table_name="sandbox_sessions")
    op.drop_index("ix_sandbox_sessions_status", table_name="sandbox_sessions")
    op.drop_index("ix_sandbox_sessions_lab_kind", table_name="sandbox_sessions")
    op.drop_index("ix_sandbox_sessions_vulnerability_id", table_name="sandbox_sessions")
    op.drop_table("sandbox_sessions")
    op.execute("DROP TYPE IF EXISTS sandbox_status_enum")
