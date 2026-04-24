from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.cve_lab_mapping import LabSourceKind
from app.models.vulnerability import _pg_enum


class SandboxStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    STOPPED = "stopped"
    EXPIRED = "expired"
    FAILED = "failed"


class SandboxSession(Base):
    """One ephemeral lab container spun up to test exploits against a CVE.

    Persisted so the UI can list/reattach to running sessions and a
    background sweeper can reap expired containers even if the API process
    is restarted between create and TTL.
    """

    __tablename__ = "sandbox_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    vulnerability_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    lab_kind: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    # Provenance of the lab spec used: vulhub | generic | synthesized.
    # Lets the UI show a "검증된 reproducer" vs "일반 클래스" badge.
    lab_source: Mapped[LabSourceKind] = mapped_column(
        _pg_enum(LabSourceKind, "lab_source_kind_enum"),
        nullable=False,
        default=LabSourceKind.GENERIC,
        index=True,
    )
    # True when this exact (cve, lab) combo had a working payload before
    # this session — i.e. ``known_good_payload`` was hit on the cache.
    verified: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    container_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    container_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    target_url: Mapped[str | None] = mapped_column(String(256), nullable=True)
    status: Mapped[SandboxStatus] = mapped_column(
        _pg_enum(SandboxStatus, "sandbox_status_enum"),
        nullable=False,
        default=SandboxStatus.PENDING,
        index=True,
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_run: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    __table_args__ = (
        Index("ix_sandbox_status_expires", "status", "expires_at"),
    )
