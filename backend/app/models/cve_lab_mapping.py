from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.vulnerability import _pg_enum


class LabSourceKind(str, enum.Enum):
    """Where a lab spec came from. Drives both resolver priority and UI badges."""

    VULHUB = "vulhub"  # curated CVE-specific reproducer (highest fidelity)
    GENERIC = "generic"  # one of the in-code class labs (xss, sqli, …)
    SYNTHESIZED = "synthesized"  # AI-built Dockerfile + app for this CVE


class CveLabMapping(Base):
    """Per-CVE pointer to a runnable lab + cached AI-adapted payload.

    Three flavors share this row shape:
      - ``vulhub``:  pre-curated, ``spec`` describes a fixed compose/image stack.
      - ``generic``: auto-created on first successful exec against an in-code
        class lab; ``spec`` may be empty (resolver re-fetches the LabDefinition
        from code) and the row exists *only* to cache ``known_good_payload``.
      - ``synthesized``: produced by the AI lab synthesizer (PR9-D) — ``spec``
        contains the built image tag + injection points the synthesizer chose.

    The (cve_id, kind) pair is unique so a CVE can have at most one row per
    kind. The resolver prefers vulhub > synthesized > generic.
    """

    __tablename__ = "cve_lab_mappings"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    kind: Mapped[LabSourceKind] = mapped_column(
        _pg_enum(LabSourceKind, "lab_source_kind_enum"),
        nullable=False,
        index=True,
    )
    # Class-level identifier within the kind: for vulhub a path like
    # "spring/CVE-2022-22965"; for generic the class key ("xss"); for
    # synthesized a content hash of the synthesis inputs.
    lab_kind: Mapped[str] = mapped_column(String(128), nullable=False)
    spec: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    known_good_payload: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Stamped every time the resolver kicks off an AI synthesis attempt for
    # this CVE — even if the attempt fails. Drives the 24h rate limit so a
    # persistently un-synthesizable CVE doesn't burn LLM tokens on repeat.
    last_synthesis_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Stamped each time this mapping is used to spawn a sandbox session.
    # Drives LRU eviction in the synthesizer GC (PR9-F): hot images stay,
    # cold ones get pruned when the disk/count ceiling is hit.
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint("cve_id", "kind", name="uq_cve_lab_mappings_cve_kind"),
        Index("ix_cve_lab_mappings_kind_verified", "kind", "verified"),
    )
