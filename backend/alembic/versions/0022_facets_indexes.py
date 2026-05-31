"""Indexes for /search/facets hot queries (PR 10-DA).

기존 facets endpoint 가 300k+ row 풀스캔으로 2.5초 걸리던 query 들을 위해
인덱스 추가:

  - ``vulnerabilities(severity)`` — severity GROUP BY
  - ``vulnerabilities(source)`` — source GROUP BY
  - ``vulnerabilities.domains`` GIN — domains TEXT[] unnest
  - ``affected_products(vulnerability_id, os_family)`` — os_family GROUP BY

각 인덱스 빌드는 300k 행 기준 10-30초. CONCURRENTLY 옵션은 Alembic
DDL 트랜잭션 안에서 못 쓰므로 그냥 만든다 (운영 첫 적용 1회만).

Revision ID: 0022
Revises: 0021
Create Date: 2026-05-31
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: Union[str, None] = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 일부 인덱스는 이전 마이그레이션 또는 부팅 시 idempotent 코드에서 만들어졌을 수
    # 있어 IF NOT EXISTS 로 안전하게.
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_vuln_severity_facets "
        "ON vulnerabilities (severity) WHERE severity IS NOT NULL"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_vuln_source_facets "
        "ON vulnerabilities (source)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_vuln_domains_gin "
        "ON vulnerabilities USING gin (domains)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_affected_vuln_os "
        "ON affected_products (vulnerability_id, os_family)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_affected_vuln_os")
    op.execute("DROP INDEX IF EXISTS ix_vuln_domains_gin")
    op.execute("DROP INDEX IF EXISTS ix_vuln_source_facets")
    op.execute("DROP INDEX IF EXISTS ix_vuln_severity_facets")
