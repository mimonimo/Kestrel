"""user_assets + notifications + notification_channels (PR 10-FB).

자산 매칭 알림 기반. 로그인 사용자의 자산을 서버에 영속화(user_assets)하고,
수집 훅이 새 CVE 매칭 시 인앱 알림(notifications) + 외부 채널(Slack/Discord
웹훅, notification_channels) 로 전달한다.

Revision ID: 0026
Revises: 0025
Create Date: 2026-06-06
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0026"
down_revision: Union[str, None] = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_assets",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("vendor", sa.String(length=120), nullable=False),
        sa.Column("product", sa.String(length=200), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("user_id", "vendor", "product", name="uq_user_asset"),
    )
    op.create_index("ix_user_asset_user", "user_assets", ["user_id"])

    op.create_table(
        "notification_channels",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("url", sa.String(length=500), nullable=False),
        sa.Column(
            "enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_notif_channel_user", "notification_channels", ["user_id"])

    op.create_table(
        "notifications",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("vendor", sa.String(length=120), nullable=True),
        sa.Column("product", sa.String(length=200), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=True),
        sa.Column("title", sa.String(length=300), nullable=True),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "uq_notif_user_cve_product",
        "notifications",
        ["user_id", "cve_id", "product"],
        unique=True,
    )
    op.create_index(
        "ix_notif_user_created", "notifications", ["user_id", "created_at"]
    )
    op.create_index(
        "ix_notif_user_unread", "notifications", ["user_id", "read_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_notif_user_unread", table_name="notifications")
    op.drop_index("ix_notif_user_created", table_name="notifications")
    op.drop_index("uq_notif_user_cve_product", table_name="notifications")
    op.drop_table("notifications")
    op.drop_index("ix_notif_channel_user", table_name="notification_channels")
    op.drop_table("notification_channels")
    op.drop_index("ix_user_asset_user", table_name="user_assets")
    op.drop_table("user_assets")
