"""KEV + EPSS priority signals on Vulnerability (PR 10-BR)

Adds the three pillars that drive the "What to Fix First" dashboard:

- ``kev_listed`` (bool) — CISA Known Exploited Vulnerabilities catalog
  membership. True = adversaries have actually exploited this in the
  wild (CISA observation), so it's the strongest priority signal.
- ``kev_date_added`` / ``kev_due_date`` (date) — CISA's bookkeeping for
  KEV entries; date_added timestamps when CISA confirmed exploitation,
  due_date is the federal patch deadline.
- ``epss_score`` (float, 0-1) — FIRST.org EPSS probability that this
  CVE will be exploited in the next 30 days. Independent of CVSS, so
  it complements (rather than duplicates) severity.
- ``epss_percentile`` (float, 0-1) — Where this CVE sits in the global
  EPSS distribution. More useful than raw score for ranking.
- ``epss_updated_at`` (datetime) — When EPSS data was last refreshed
  for this row; lets the UI flag stale scores.

Backfill leaves everything NULL/false — the new collectors populate
these on next ingest run.

Revision ID: 0019
Revises: 0018
Create Date: 2026-05-23
"""
from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0019"
down_revision: Union[str, None] = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column("kev_listed", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("kev_date_added", sa.Date(), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("kev_due_date", sa.Date(), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("epss_score", sa.Float(), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("epss_percentile", sa.Float(), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("epss_updated_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Partial indexes for the ranking queries — the WhatToFixFirst panel
    # constantly filters on (kev_listed=true) and (epss_score >= 0.5),
    # so dedicated indexes keep that fast even at 10M+ rows.
    op.create_index(
        "ix_vuln_kev_listed",
        "vulnerabilities",
        ["kev_listed"],
        postgresql_where=sa.text("kev_listed = true"),
    )
    op.create_index(
        "ix_vuln_epss_score_desc",
        "vulnerabilities",
        [sa.text("epss_score DESC")],
        postgresql_where=sa.text("epss_score IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_vuln_epss_score_desc", table_name="vulnerabilities")
    op.drop_index("ix_vuln_kev_listed", table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "epss_updated_at")
    op.drop_column("vulnerabilities", "epss_percentile")
    op.drop_column("vulnerabilities", "epss_score")
    op.drop_column("vulnerabilities", "kev_due_date")
    op.drop_column("vulnerabilities", "kev_date_added")
    op.drop_column("vulnerabilities", "kev_listed")
