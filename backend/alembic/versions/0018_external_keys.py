"""Server-side persisted NVD/GitHub API keys (PR 10-AJ).

Until now the only path for users to inject their NVD API key or
GitHub token was per-request via X-NVD-API-Key / X-GitHub-Token
headers from the dashboard's /admin/refresh button. The scheduler
runs in the background and never sees those headers, so its periodic
runs always fired token-less — GHSA in particular returned zero rows
because GitHub's GraphQL API rejects unauthenticated calls.

Adds two nullable columns on the singleton ``app_settings`` row so
the dashboard can persist these keys server-side; parsers fall back
to them when the env vars are unset.

Revision ID: 0018
Revises: 0017
Create Date: 2026-05-10
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: Union[str, None] = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column("nvd_api_key", sa.Text(), nullable=True),
    )
    op.add_column(
        "app_settings",
        sa.Column("github_token", sa.Text(), nullable=True),
    )

    # Backfill — clean nonsensical publishedAt values introduced by the
    # Exploit-DB parser (which used to set the *exploit* date as the CVE
    # publishedAt). The first CVE was assigned in 1999-09; anything
    # before then is wrong. We also conservatively NULL out rows whose
    # year is < the YYYY embedded in the CVE id (CVE-2000-* with
    # publishedAt=1990 etc). NULL lets NVD/MITRE refill the correct
    # date on their next sync.
    op.execute(
        "UPDATE vulnerabilities SET published_at = NULL "
        "WHERE published_at < '1999-09-01'"
    )
    op.execute(
        """
        UPDATE vulnerabilities
        SET published_at = NULL
        WHERE published_at IS NOT NULL
          AND cve_id ~ '^CVE-[0-9]{4}-'
          AND EXTRACT(YEAR FROM published_at)::int
              < CAST(SUBSTRING(cve_id FROM 5 FOR 4) AS INT)
        """
    )


def downgrade() -> None:
    op.drop_column("app_settings", "github_token")
    op.drop_column("app_settings", "nvd_api_key")
