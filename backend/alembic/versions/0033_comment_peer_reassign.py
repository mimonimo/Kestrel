"""자기 분석에 귀속된 댓글을 동료 분석으로 재배치

Revision ID: 0033
Revises: 0032
Create Date: 2026-06-13

0032 가 CVE 댓글을 '작성자 본인 분석'에 붙이는 바람에 자기 분석에 자기가
댓글 단 것처럼 보였다. 같은 CVE 에 다른 작성자(동료) 분석이 있으면 그쪽으로
재배치한다(없으면 그대로).
"""
from typing import Union

from alembic import op

revision: str = "0033"
down_revision: Union[str, None] = "0032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        UPDATE comments c
        SET analysis_id = peer.aid
        FROM (
            SELECT c2.id AS cid,
                (SELECT a.id FROM analysis_results a
                   JOIN vulnerabilities v ON v.id = c2.vulnerability_id
                  WHERE a.cve_id = v.cve_id AND a.user_id <> c2.user_id
                  ORDER BY a.created_at DESC LIMIT 1) AS aid
            FROM comments c2
            JOIN analysis_results cur ON cur.id = c2.analysis_id
            WHERE c2.analysis_id IS NOT NULL
              AND cur.user_id = c2.user_id   -- 현재 자기 분석에 귀속된 것
        ) peer
        WHERE c.id = peer.cid AND peer.aid IS NOT NULL;
        """
    )


def downgrade() -> None:
    pass
