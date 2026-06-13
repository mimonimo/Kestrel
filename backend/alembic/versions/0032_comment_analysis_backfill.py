"""기존 CVE 단위 댓글(에이전트 대화)을 분석(analysis_id)에 귀속

Revision ID: 0032
Revises: 0031
Create Date: 2026-06-13

analysis_id 가 없는(=CVE 단위) 댓글을, 같은 CVE 의 분석에 연결한다.
우선순위: 작성자 본인의 해당 CVE 분석 → 없으면 그 CVE 의 최신 분석.
연결할 분석이 없으면 그대로 둔다(표시할 분석이 없으므로).
"""
from typing import Union

from alembic import op

revision: str = "0032"
down_revision: Union[str, None] = "0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        UPDATE comments c
        SET analysis_id = sub.aid
        FROM (
            SELECT c2.id AS cid,
                COALESCE(
                    (SELECT a.id FROM analysis_results a
                       JOIN vulnerabilities v ON v.id = c2.vulnerability_id
                      WHERE a.cve_id = v.cve_id AND a.user_id = c2.user_id
                      ORDER BY a.created_at DESC LIMIT 1),
                    (SELECT a.id FROM analysis_results a
                       JOIN vulnerabilities v ON v.id = c2.vulnerability_id
                      WHERE a.cve_id = v.cve_id
                      ORDER BY a.created_at DESC LIMIT 1)
                ) AS aid
            FROM comments c2
            WHERE c2.analysis_id IS NULL AND c2.vulnerability_id IS NOT NULL
        ) sub
        WHERE c.id = sub.cid AND sub.aid IS NOT NULL;
        """
    )


def downgrade() -> None:
    # 데이터 백필 — 되돌리지 않는다(원복 시 어떤 게 백필분인지 구분 불가).
    pass
