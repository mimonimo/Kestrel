"""vulnerabilities 에이전트 우선순위 정렬용 복합 인덱스

``GET /agent/cves`` 는 ``(kev_listed OR cvss_score>=7)`` 필터 + ``kev_listed DESC,
cvss_score DESC NULLS LAST, published_at DESC NULLS LAST`` 정렬로 상위 N 건을
뽑는다. 이 다중키 정렬에 맞는 인덱스가 없어 37만 행을 통째로 정렬 → LIMIT 1
조차 20초 statement timeout 을 넘겨 500(QueryCanceledError)이 났다. 정렬 순서와
동일한 복합 인덱스를 두면 인덱스 스캔 + LIMIT 으로 즉시 반환된다.

멱등(``IF NOT EXISTS``): 운영 DB 는 이미 ``CREATE INDEX CONCURRENTLY`` 로 선반영
되어 있어 no-op, 신규/개발 DB 에서는 이 마이그레이션이 생성한다.

Revision ID: 0040
Revises: 0039
Create Date: 2026-07-31
"""
from typing import Union

from alembic import op

revision: str = "0040"
down_revision: Union[str, None] = "0039"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_vuln_agent_priority "
        "ON vulnerabilities "
        "(kev_listed DESC, cvss_score DESC NULLS LAST, published_at DESC NULLS LAST)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_vuln_agent_priority")
