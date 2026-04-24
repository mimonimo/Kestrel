"""cve lab mappings

Revision ID: 0010
Revises: 0009
Create Date: 2026-04-24
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "DO $$ BEGIN "
        "CREATE TYPE lab_source_kind_enum AS ENUM "
        "('vulhub', 'generic', 'synthesized'); "
        "EXCEPTION WHEN duplicate_object THEN null; END $$;"
    )
    op.create_table(
        "cve_lab_mappings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column(
            "kind",
            postgresql.ENUM(
                "vulhub",
                "generic",
                "synthesized",
                name="lab_source_kind_enum",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("lab_kind", sa.String(length=128), nullable=False),
        sa.Column(
            "spec",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("known_good_payload", postgresql.JSONB(), nullable=True),
        sa.Column(
            "verified",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
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
        sa.UniqueConstraint("cve_id", "kind", name="uq_cve_lab_mappings_cve_kind"),
    )
    op.create_index(
        "ix_cve_lab_mappings_cve_id", "cve_lab_mappings", ["cve_id"]
    )
    op.create_index("ix_cve_lab_mappings_kind", "cve_lab_mappings", ["kind"])
    op.create_index(
        "ix_cve_lab_mappings_kind_verified",
        "cve_lab_mappings",
        ["kind", "verified"],
    )


def downgrade() -> None:
    op.drop_index("ix_cve_lab_mappings_kind_verified", table_name="cve_lab_mappings")
    op.drop_index("ix_cve_lab_mappings_kind", table_name="cve_lab_mappings")
    op.drop_index("ix_cve_lab_mappings_cve_id", table_name="cve_lab_mappings")
    op.drop_table("cve_lab_mappings")
    op.execute("DROP TYPE IF EXISTS lab_source_kind_enum")
