"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-04-19

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels = None
depends_on = None


def _create_enum_if_missing(name: str, values: tuple[str, ...]) -> None:
    quoted = ", ".join(f"'{v}'" for v in values)
    op.execute(
        f"""
        DO $$ BEGIN
          CREATE TYPE {name} AS ENUM ({quoted});
        EXCEPTION WHEN duplicate_object THEN null;
        END $$;
        """
    )


def upgrade() -> None:
    # --- Enums ---
    # SQLAlchemy's Enum auto-create has multi-reference duplication issues
    # under asyncpg + alembic. Plain DO blocks keep the migration idempotent
    # and let every Column below safely reference the type via postgresql.ENUM
    # with create_type=False.
    _create_enum_if_missing("severity_enum", ("low", "medium", "high", "critical"))
    _create_enum_if_missing(
        "os_family_enum", ("windows", "linux", "macos", "android", "ios", "other")
    )
    _create_enum_if_missing("source_enum", ("nvd", "exploit_db", "github_advisory"))
    _create_enum_if_missing("ref_type_enum", ("advisory", "exploit", "patch", "writeup"))
    _create_enum_if_missing("user_role_enum", ("user", "expert", "admin"))
    _create_enum_if_missing(
        "vote_target_enum", ("post", "comment", "vulnerability")
    )

    severity_enum = postgresql.ENUM(
        "low", "medium", "high", "critical", name="severity_enum", create_type=False
    )
    os_family_enum = postgresql.ENUM(
        "windows", "linux", "macos", "android", "ios", "other",
        name="os_family_enum", create_type=False,
    )
    source_enum = postgresql.ENUM(
        "nvd", "exploit_db", "github_advisory", name="source_enum", create_type=False
    )
    ref_type_enum = postgresql.ENUM(
        "advisory", "exploit", "patch", "writeup", name="ref_type_enum", create_type=False
    )
    user_role_enum = postgresql.ENUM(
        "user", "expert", "admin", name="user_role_enum", create_type=False
    )
    vote_target_enum = postgresql.ENUM(
        "post", "comment", "vulnerability", name="vote_target_enum", create_type=False
    )

    # --- vulnerability_types ---
    op.create_table(
        "vulnerability_types",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("cwe_id", sa.String(16)),
        sa.Column("description", sa.Text),
    )
    op.create_index("ix_vulnerability_types_name", "vulnerability_types", ["name"])

    # --- vulnerabilities ---
    op.create_table(
        "vulnerabilities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cve_id", sa.String(32), nullable=False, unique=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("summary", sa.String(500)),
        sa.Column("cvss_score", sa.Numeric(3, 1)),
        sa.Column("cvss_vector", sa.String(128)),
        sa.Column("severity", severity_enum),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("modified_at", sa.DateTime(timezone=True)),
        sa.Column("source", source_enum, nullable=False),
        sa.Column("source_url", sa.Text, nullable=False),
        sa.Column("raw_data", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("search_vector", postgresql.TSVECTOR),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_vulnerabilities_cve_id", "vulnerabilities", ["cve_id"])
    op.create_index("ix_vulnerabilities_severity", "vulnerabilities", ["severity"])
    op.create_index("ix_vuln_published_desc", "vulnerabilities", ["published_at"])
    op.create_index(
        "ix_vuln_search_vector", "vulnerabilities", ["search_vector"], postgresql_using="gin"
    )

    # Trigger to keep search_vector in sync
    op.execute(
        """
        CREATE OR REPLACE FUNCTION vulnerabilities_search_vector_update() RETURNS trigger AS $$
        BEGIN
          NEW.search_vector :=
            setweight(to_tsvector('simple', coalesce(NEW.cve_id, '')), 'A') ||
            setweight(to_tsvector('simple', coalesce(NEW.title, '')), 'B') ||
            setweight(to_tsvector('simple', coalesce(NEW.summary, '')), 'C') ||
            setweight(to_tsvector('simple', coalesce(NEW.description, '')), 'D');
          RETURN NEW;
        END
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER vulnerabilities_search_vector_trigger
        BEFORE INSERT OR UPDATE ON vulnerabilities
        FOR EACH ROW EXECUTE FUNCTION vulnerabilities_search_vector_update();
        """
    )

    # --- vulnerability_type_map ---
    op.create_table(
        "vulnerability_type_map",
        sa.Column(
            "vulnerability_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "type_id",
            sa.Integer,
            sa.ForeignKey("vulnerability_types.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )

    # --- affected_products ---
    op.create_table(
        "affected_products",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "vulnerability_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("vendor", sa.String(128)),
        sa.Column("product", sa.String(128)),
        sa.Column("os_family", os_family_enum, nullable=False, server_default="other"),
        sa.Column("version_range", sa.String(128)),
        sa.Column("cpe_string", sa.String(256)),
    )
    op.create_index("ix_ap_vuln_id", "affected_products", ["vulnerability_id"])
    op.create_index("ix_ap_os_family", "affected_products", ["os_family"])
    op.create_index("ix_ap_vendor", "affected_products", ["vendor"])
    op.create_index("ix_ap_product", "affected_products", ["product"])

    # --- references ---
    op.create_table(
        "references",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "vulnerability_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("ref_type", ref_type_enum, nullable=False, server_default="advisory"),
    )
    op.create_index("ix_references_vuln_id", "references", ["vulnerability_id"])

    # --- ingestion_logs ---
    op.create_table(
        "ingestion_logs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("source", source_enum, nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("items_processed", sa.Integer, server_default="0"),
        sa.Column("items_new", sa.Integer, server_default="0"),
        sa.Column("items_updated", sa.Integer, server_default="0"),
        sa.Column("status", sa.String(32), server_default="running"),
        sa.Column("error_message", sa.Text),
        sa.Column("meta", sa.JSON, server_default="{}"),
    )
    op.create_index("ix_ingestion_logs_source", "ingestion_logs", ["source"])

    # --- users ---
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", user_role_enum, nullable=False, server_default="user"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    # --- posts / comments / votes / tags ---
    op.create_table(
        "posts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "vulnerability_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("view_count", sa.Integer, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_posts_vuln_id", "posts", ["vulnerability_id"])

    op.create_table(
        "comments",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("post_id", sa.Integer, sa.ForeignKey("posts.id", ondelete="CASCADE")),
        sa.Column(
            "vulnerability_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("parent_id", sa.Integer, sa.ForeignKey("comments.id", ondelete="CASCADE")),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_comments_post_id", "comments", ["post_id"])
    op.create_index("ix_comments_vuln_id", "comments", ["vulnerability_id"])

    op.create_table(
        "votes",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("target_type", vote_target_enum, nullable=False),
        sa.Column("target_id", sa.String(64), nullable=False),
        sa.Column("vote_type", sa.Integer, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_vote_target", "votes", ["target_type", "target_id"])
    op.create_index(
        "ix_vote_user_target", "votes", ["user_id", "target_type", "target_id"], unique=True
    )

    op.create_table(
        "tags",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
    )
    op.create_index("ix_tags_name", "tags", ["name"])


def downgrade() -> None:
    op.drop_table("tags")
    op.drop_table("votes")
    op.drop_table("comments")
    op.drop_table("posts")
    op.drop_table("users")
    op.drop_table("ingestion_logs")
    op.drop_table("references")
    op.drop_table("affected_products")
    op.drop_table("vulnerability_type_map")
    op.execute("DROP TRIGGER IF EXISTS vulnerabilities_search_vector_trigger ON vulnerabilities")
    op.execute("DROP FUNCTION IF EXISTS vulnerabilities_search_vector_update")
    op.drop_table("vulnerabilities")
    op.drop_table("vulnerability_types")
    for name in (
        "severity_enum",
        "os_family_enum",
        "source_enum",
        "ref_type_enum",
        "user_role_enum",
        "vote_target_enum",
    ):
        op.execute(f"DROP TYPE IF EXISTS {name}")
