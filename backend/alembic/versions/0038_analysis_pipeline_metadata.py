"""analysis_results 파이프라인 구조화 메타데이터 컬럼

외부 에이전트의 7단계 분석 파이프라인(CVSS+EPSS+KEV 융합, 교차검증,
우선순위 산출)이 산출하는 구조화 값이 지금은 result_md 마크다운에 뭉개진다.
이를 컬럼으로 받아 UI 가 뱃지·정렬 등에 쓸 수 있게 한다.

- ``epss_score`` / ``epss_percentile`` (float, 0~1) — 분석 시점 EPSS 스냅샷.
  vulnerabilities 의 동명 컬럼은 CVE 의 *현재* 신호라 별개.
- ``priority_action`` (str) — immediate / scheduled / monitor.
- ``priority_reasoning`` (text) — "KEV floor applied..." 같은 산출 근거.
- ``kev_listed`` (bool) — 분석 시점 KEV 등재 여부 스냅샷.
- ``validation_confidence`` (float, 0~1) — 교차검증 신뢰도.
- ``exploitability_grade`` (str) — easy / moderate / hard.
- ``quality_flags`` (jsonb) — likely_supply_chain 등 품질 플래그.
- ``pipeline_version`` (str) — 생성 파이프라인 식별자.

전부 nullable — 기존 분석은 NULL 로 남고(무손상), 값이 있으면 파이프라인産
분석으로 구분한다.

Revision ID: 0038
Revises: 0037
Create Date: 2026-07-10
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0038"
down_revision: Union[str, None] = "0037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("analysis_results", sa.Column("epss_score", sa.Float(), nullable=True))
    op.add_column("analysis_results", sa.Column("epss_percentile", sa.Float(), nullable=True))
    op.add_column("analysis_results", sa.Column("priority_action", sa.String(16), nullable=True))
    op.add_column("analysis_results", sa.Column("priority_reasoning", sa.Text(), nullable=True))
    op.add_column("analysis_results", sa.Column("kev_listed", sa.Boolean(), nullable=True))
    op.add_column(
        "analysis_results", sa.Column("validation_confidence", sa.Float(), nullable=True)
    )
    op.add_column(
        "analysis_results", sa.Column("exploitability_grade", sa.String(16), nullable=True)
    )
    op.add_column("analysis_results", sa.Column("quality_flags", postgresql.JSONB(), nullable=True))
    op.add_column("analysis_results", sa.Column("pipeline_version", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("analysis_results", "pipeline_version")
    op.drop_column("analysis_results", "quality_flags")
    op.drop_column("analysis_results", "exploitability_grade")
    op.drop_column("analysis_results", "validation_confidence")
    op.drop_column("analysis_results", "kev_listed")
    op.drop_column("analysis_results", "priority_reasoning")
    op.drop_column("analysis_results", "priority_action")
    op.drop_column("analysis_results", "epss_percentile")
    op.drop_column("analysis_results", "epss_score")
