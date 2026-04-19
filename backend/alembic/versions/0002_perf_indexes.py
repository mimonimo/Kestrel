"""performance indexes

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-20

Step 5 — 대시보드 기본 동작(필터 + 정렬)을 기준으로 추가되는 복합/정렬 인덱스.
필터가 많아지는 경로에서 plain B-tree 단일 컬럼 인덱스의 조합만으로는
sort+filter가 같이 들어오는 쿼리를 커버하지 못한다. 특히 상세 페이지 진입이 잦은
(severity, published_at desc) 경로와 OS 필터 → 취약점 조인 경로를 최적화한다.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Severity + published_at: 대시보드 최신순 + 심각도 필터 조합의 핵심 경로
    op.create_index(
        "ix_vuln_severity_published",
        "vulnerabilities",
        ["severity", sa.text("published_at DESC NULLS LAST")],
    )

    # 정렬 전용 내림차순: published_at 단독 정렬 시 nulls_last 힌트를 활용
    op.drop_index("ix_vuln_published_desc", table_name="vulnerabilities")
    op.create_index(
        "ix_vuln_published_desc",
        "vulnerabilities",
        [sa.text("published_at DESC NULLS LAST")],
    )

    # Source + published_at: 소스별 최근 수집 현황 조회용
    op.create_index(
        "ix_vuln_source_published",
        "vulnerabilities",
        ["source", sa.text("published_at DESC NULLS LAST")],
    )

    # affected_products: OS 필터 후 vuln join (OS → vuln_id 순)
    op.drop_index("ix_ap_os_family", table_name="affected_products")
    op.create_index(
        "ix_ap_os_vuln",
        "affected_products",
        ["os_family", "vulnerability_id"],
    )

    # vulnerability_type_map: type_id 단독 인덱스 없음 → type → vuln 조회 보강
    op.create_index(
        "ix_vtm_type_vuln",
        "vulnerability_type_map",
        ["type_id", "vulnerability_id"],
    )

    # ingestion_logs: 소스별 최근 실행 조회 (헬스체크용)
    op.create_index(
        "ix_ingestion_source_started",
        "ingestion_logs",
        ["source", sa.text("started_at DESC")],
    )


def downgrade() -> None:
    op.drop_index("ix_ingestion_source_started", table_name="ingestion_logs")
    op.drop_index("ix_vtm_type_vuln", table_name="vulnerability_type_map")
    op.drop_index("ix_ap_os_vuln", table_name="affected_products")
    op.create_index("ix_ap_os_family", "affected_products", ["os_family"])
    op.drop_index("ix_vuln_source_published", table_name="vulnerabilities")
    op.drop_index("ix_vuln_published_desc", table_name="vulnerabilities")
    op.create_index("ix_vuln_published_desc", "vulnerabilities", ["published_at"])
    op.drop_index("ix_vuln_severity_published", table_name="vulnerabilities")
