"""Application settings API.

Stores the AI analyzer credentials (provider / model / API key) in a single
DB row. The API key is write-only — GET responses redact it to a boolean
``hasApiKey`` flag so the frontend never receives the secret back. Sending
``aiApiKey: null`` or an empty string clears the stored key; omitting the
field leaves it unchanged.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import AppSettings
from app.schemas.vulnerability import CamelModel

router = APIRouter(prefix="/settings", tags=["settings"])


class SettingsOut(CamelModel):
    ai_provider: str | None = None
    ai_model: str | None = None
    has_api_key: bool = False


class SettingsUpdate(CamelModel):
    ai_provider: str | None = Field(default=None, max_length=32)
    ai_model: str | None = Field(default=None, max_length=64)
    ai_api_key: str | None = Field(default=None)


async def _load(db: AsyncSession) -> AppSettings:
    row = (await db.execute(select(AppSettings).where(AppSettings.id == 1))).scalar_one_or_none()
    if row is None:
        row = AppSettings(id=1)
        db.add(row)
        await db.flush()
    return row


@router.get("", response_model=SettingsOut, response_model_by_alias=True)
async def get_settings(db: AsyncSession = Depends(get_db)) -> SettingsOut:
    row = await _load(db)
    return SettingsOut(
        ai_provider=row.ai_provider,
        ai_model=row.ai_model,
        has_api_key=bool(row.ai_api_key),
    )


@router.put("", response_model=SettingsOut, response_model_by_alias=True)
async def update_settings(
    body: SettingsUpdate,
    db: AsyncSession = Depends(get_db),
) -> SettingsOut:
    row = await _load(db)
    # `model_fields_set` reflects the original keys from the request, so
    # `populate_by_name=True` means either snake_case or camelCase may appear.
    fields = body.model_fields_set
    if "ai_provider" in fields or "aiProvider" in fields:
        row.ai_provider = body.ai_provider or None
    if "ai_model" in fields or "aiModel" in fields:
        row.ai_model = body.ai_model or None
    if "ai_api_key" in fields or "aiApiKey" in fields:
        row.ai_api_key = body.ai_api_key or None
    await db.commit()
    await db.refresh(row)
    return SettingsOut(
        ai_provider=row.ai_provider,
        ai_model=row.ai_model,
        has_api_key=bool(row.ai_api_key),
    )
