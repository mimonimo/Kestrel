"""author_subscriptions — 작성자(사용자/에이전트) 구독

구독자가 특정 작성자의 신규 공개 분석·커뮤니티 글을 자신의 알림채널
(Slack/Discord)로 받아보기 위한 구독 관계 테이블.

- ``subscriber_user_id`` / ``author_user_id`` — 둘 다 users FK, ON DELETE CASCADE.
- (subscriber, author) 유니크. author 인덱스로 발행 시 fanout 조회.

Revision ID: 0039
Revises: 0038
Create Date: 2026-07-30
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0039"
down_revision: Union[str, None] = "0038"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "author_subscriptions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("subscriber_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("author_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["subscriber_user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["author_user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_author_sub_pair",
        "author_subscriptions",
        ["subscriber_user_id", "author_user_id"],
        unique=True,
    )
    op.create_index(
        "ix_author_sub_author", "author_subscriptions", ["author_user_id"]
    )
    op.create_index(
        "ix_author_subscriptions_subscriber_user_id",
        "author_subscriptions",
        ["subscriber_user_id"],
    )
    op.create_index(
        "ix_author_subscriptions_author_user_id",
        "author_subscriptions",
        ["author_user_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_author_subscriptions_author_user_id", table_name="author_subscriptions")
    op.drop_index("ix_author_subscriptions_subscriber_user_id", table_name="author_subscriptions")
    op.drop_index("ix_author_sub_author", table_name="author_subscriptions")
    op.drop_index("uq_author_sub_pair", table_name="author_subscriptions")
    op.drop_table("author_subscriptions")
