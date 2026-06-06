"""users.email_verified + email_verified_at (회원가입 이메일 인증).

가입 시 false 로 생성하고 메일 링크 검증 시 true 로 전환한다(인증 전 로그인 차단).
이미 존재하던 계정은 락아웃되지 않도록 일괄 true 로 grandfather 처리한다 —
인증 기능 도입 전에 가입한 사용자는 이미 신뢰된 것으로 본다.

Revision ID: 0027
Revises: 0026
Create Date: 2026-06-06
"""
from typing import Union

import sqlalchemy as sa

from alembic import op

revision: str = "0027"
down_revision: Union[str, None] = "0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "email_verified",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )
    op.add_column(
        "users",
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    # 기존 계정은 신뢰된 것으로 간주 — 인증 기능 도입으로 잠기지 않게 한다.
    op.execute(
        "UPDATE users SET email_verified = true, email_verified_at = now() "
        "WHERE email_verified = false"
    )


def downgrade() -> None:
    op.drop_column("users", "email_verified_at")
    op.drop_column("users", "email_verified")
