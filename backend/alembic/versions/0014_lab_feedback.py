"""cve_lab_feedback table + denormalized counters on cve_lab_mappings (PR9-J)

The synthesized lab cache survives across many users — we want a way to
demote labs that consistently misfire without operator intervention. Per-
client votes go in ``cve_lab_feedback`` (one row per (mapping, client),
upserted on revote); the up/down counts are denormalized on the mapping
so the resolver can decide ``degraded?`` in O(1) without joining.

Revision ID: 0014
Revises: 0013
Create Date: 2026-04-25
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "cve_lab_mappings",
        sa.Column(
            "feedback_up",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "cve_lab_mappings",
        sa.Column(
            "feedback_down",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )

    op.create_table(
        "cve_lab_feedback",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "mapping_id",
            sa.Integer(),
            sa.ForeignKey("cve_lab_mappings.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("client_id", sa.String(64), nullable=False),
        # 'up' | 'down' — kept as a short string so we can extend later
        # (e.g. 'flag') without a migration for the enum.
        sa.Column("vote", sa.String(8), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            onupdate=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint("mapping_id", "client_id", name="uq_lab_feedback_mapping_client"),
    )


def downgrade() -> None:
    op.drop_table("cve_lab_feedback")
    op.drop_column("cve_lab_mappings", "feedback_down")
    op.drop_column("cve_lab_mappings", "feedback_up")
