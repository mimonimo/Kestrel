"""vulnerabilities.domains TEXT[] for cross-domain categorization (PR 10-B)

A single CVE often affects multiple disjoint domains — e.g. an audio
codec parser bug that corrupts memory inside an SSH client embedded in
the same process. Modeling that as a single ``vulnerability_types``
label loses information; modeling it as M:N with a controlled domain
table adds joins for a value set that's small (~20 entries) and rarely
mutates. A ``TEXT[]`` column with a GIN index keeps overlap/contains
queries fast (``domains && ARRAY['audio','ssh']``) without the join.

Revision ID: 0015
Revises: 0014
Create Date: 2026-04-26
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column(
            "domains",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default="{}",
        ),
    )
    op.create_index(
        "ix_vuln_domains_gin",
        "vulnerabilities",
        ["domains"],
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_index("ix_vuln_domains_gin", table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "domains")
