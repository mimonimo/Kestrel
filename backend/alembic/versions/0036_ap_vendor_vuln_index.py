"""affected_products (vendor, vulnerability_id) 커버링 인덱스

대시보드 인사이트의 벤더 집계(count(distinct vulnerability_id) GROUP BY vendor)가
288만 행에서 vendor 단독 인덱스 + 힙 조회 + 정렬로 ~26초 걸려 백그라운드
스냅샷이 타임아웃되던 문제를 해결한다. (vendor, vulnerability_id) 복합 인덱스로
Index Only Scan + streaming GroupAggregate 가 되어 ~3.7초로 단축된다.

대용량 테이블 + 인제스션 쓰기와 충돌하지 않도록 CONCURRENTLY 로 생성한다
(autocommit_block 안에서 실행 — 트랜잭션 밖이어야 함). prod 에는 이미 수동
생성돼 있어 IF NOT EXISTS 로 no-op.

Revision ID: 0036
Revises: 0035
Create Date: 2026-06-14
"""
from typing import Union

from alembic import op

revision: str = "0036"
down_revision: Union[str, None] = "0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_ap_vendor_vuln "
            "ON affected_products (vendor, vulnerability_id)"
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_ap_vendor_vuln")
