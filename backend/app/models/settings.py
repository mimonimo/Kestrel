"""Application settings — singleton row holding server-side configuration.

Currently holds only the currently-active AI credential (FK to ai_credentials).
Individual AI credentials (label/provider/model/key/base_url) live in the
``ai_credentials`` table so the user can register multiple keys and switch
between them from the UI.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AppSettings(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    active_credential_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("ai_credentials.id", ondelete="SET NULL"),
        nullable=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
