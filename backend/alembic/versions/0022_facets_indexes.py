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
    # severity GROUP BY 가속 — NULL 제외해 size 절감.
    op.create_index(
        "ix_vuln_severity_facets",
        "vulnerabilities",
        ["severity"],
        postgresql_where=sa.text("severity IS NOT NULL"),
    )
    # source GROUP BY 가속.
    op.create_index(
        "ix_vuln_source_facets",
        "vulnerabilities",
        ["source"],
    )
    # domains TEXT[] unnest + filter — GIN array index.
    op.create_index(
        "ix_vuln_domains_gin",
        "vulnerabilities",
        ["domains"],
        postgresql_using="gin",
    )
    # affected_products os_family GROUP BY — vulnerability_id 와 함께
    # DISTINCT 카운트가 빠르게 동작하도록 복합 인덱스.
    op.create_index(
        "ix_affected_vuln_os",
        "affected_products",
        ["vulnerability_id", "os_family"],
    )


def downgrade() -> None:
    op.drop_index("ix_affected_vuln_os", table_name="affected_products")
    op.drop_index("ix_vuln_domains_gin", table_name="vulnerabilities")
    op.drop_index("ix_vuln_source_facets", table_name="vulnerabilities")
    op.drop_index("ix_vuln_severity_facets", table_name="vulnerabilities")
