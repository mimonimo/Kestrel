"""tickets

Revision ID: 0005
Revises: 0004
Create Date: 2026-04-20
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "DO $$ BEGIN "
        "CREATE TYPE ticket_status_enum AS ENUM ('open', 'in_progress', 'resolved', 'ignored'); "
        "EXCEPTION WHEN duplicate_object THEN null; END $$;"
    )
    op.create_table(
        "tickets",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(
                "open",
                "in_progress",
                "resolved",
                "ignored",
                name="ticket_status_enum",
                create_type=False,
            ),
            nullable=False,
            server_default="open",
        ),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("client_id", "cve_id", name="uq_ticket_client_cve"),
    )
    op.create_index("ix_ticket_client", "tickets", ["client_id"])
    op.create_index("ix_ticket_status", "tickets", ["client_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_ticket_status", table_name="tickets")
    op.drop_index("ix_ticket_client", table_name="tickets")
    op.drop_table("tickets")
    op.execute("DROP TYPE IF EXISTS ticket_status_enum")
