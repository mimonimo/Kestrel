"""ai credentials table — support multiple saved keys + active selector

Revision ID: 0008
Revises: 0007
Create Date: 2026-04-20
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_credentials",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("label", sa.String(length=64), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=64), nullable=False),
        sa.Column("api_key", sa.Text(), nullable=False),
        sa.Column("base_url", sa.String(length=256), nullable=True),
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
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "active_credential_id",
            sa.Integer(),
            sa.ForeignKey("ai_credentials.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    # Legacy single-credential columns on app_settings are replaced by the
    # new ai_credentials table. Drop them — DB was reset during the kestrel
    # rebrand so no data migration is required.
    op.drop_column("app_settings", "ai_base_url")
    op.drop_column("app_settings", "ai_api_key")
    op.drop_column("app_settings", "ai_model")
    op.drop_column("app_settings", "ai_provider")


def downgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column("ai_provider", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "app_settings",
        sa.Column("ai_model", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "app_settings",
        sa.Column("ai_api_key", sa.Text(), nullable=True),
    )
    op.add_column(
        "app_settings",
        sa.Column("ai_base_url", sa.String(length=256), nullable=True),
    )
    op.drop_column("app_settings", "active_credential_id")
    op.drop_table("ai_credentials")
