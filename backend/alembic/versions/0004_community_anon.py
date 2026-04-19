"""community: allow anonymous posts/comments

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-20

Kestrel ships without auth, so posts and comments can no longer hard-require a
`users.id`. We make `user_id` nullable, switch the FK to ON DELETE SET NULL,
and add `client_id` (browser-issued UUID) plus a display `author_name`.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("posts", "comments"):
        op.alter_column(table, "user_id", existing_type=sa.dialects.postgresql.UUID(), nullable=True)

        op.drop_constraint(f"{table}_user_id_fkey", table, type_="foreignkey")
        op.create_foreign_key(
            f"{table}_user_id_fkey",
            table,
            "users",
            ["user_id"],
            ["id"],
            ondelete="SET NULL",
        )

        op.add_column(table, sa.Column("client_id", sa.String(length=64), nullable=True))
        op.add_column(
            table,
            sa.Column(
                "author_name",
                sa.String(length=64),
                nullable=False,
                server_default="익명",
            ),
        )
        op.create_index(f"ix_{table}_client_id", table, ["client_id"])


def downgrade() -> None:
    for table in ("posts", "comments"):
        op.drop_index(f"ix_{table}_client_id", table_name=table)
        op.drop_column(table, "author_name")
        op.drop_column(table, "client_id")

        op.drop_constraint(f"{table}_user_id_fkey", table, type_="foreignkey")
        op.create_foreign_key(
            f"{table}_user_id_fkey",
            table,
            "users",
            ["user_id"],
            ["id"],
            ondelete="CASCADE",
        )
        op.alter_column(table, "user_id", existing_type=sa.dialects.postgresql.UUID(), nullable=False)
