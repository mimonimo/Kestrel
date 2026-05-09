"""MITRE source + multi-source tracking (PR 10-AF)

Adds:
- 'mitre' value to source_enum so the MITRE cvelistV5 importer can write
  rows with that origin.
- vulnerabilities.sources TEXT[] tracking *every* upstream feed that
  contributed to a CVE row. The legacy ``source`` column stays as the
  primary attribution for back-compat (existing UI badges keep working);
  the array is the canonical multi-source field that new UI and
  filters consume. GIN index keeps ``sources && ARRAY['mitre']`` lookups
  fast.

Backfill copies the existing single ``source`` into ``sources`` so
historical rows show their original feed in the new array column.

Revision ID: 0017
Revises: 0016
Create Date: 2026-05-09
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0017"
down_revision: Union[str, None] = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1) Extend the source_enum with 'mitre'. Postgres doesn't allow
    # ALTER TYPE ... ADD VALUE inside a transaction in some versions —
    # use the connection autocommit shim that alembic provides.
    op.execute("ALTER TYPE source_enum ADD VALUE IF NOT EXISTS 'mitre'")

    # 2) Add the array column with empty default.
    op.add_column(
        "vulnerabilities",
        sa.Column(
            "sources",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default="{}",
        ),
    )

    # 3) Backfill: every existing row gets ARRAY[source::text]. Single
    # UPDATE — no batching needed (95k rows is a couple of seconds).
    op.execute(
        "UPDATE vulnerabilities SET sources = ARRAY[source::text] "
        "WHERE cardinality(sources) = 0"
    )

    # 4) GIN index for overlap/contains lookups. Same pattern as
    # ``ix_vuln_domains_gin``.
    op.create_index(
        "ix_vuln_sources_gin",
        "vulnerabilities",
        ["sources"],
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_index("ix_vuln_sources_gin", table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "sources")
    # Note: PostgreSQL doesn't support removing enum values without
    # rewriting the type. We leave 'mitre' in place — harmless if
    # unused. To fully remove, recreate source_enum with the original
    # 3 values and ALTER COLUMN to use the new type.
