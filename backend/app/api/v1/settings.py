"""Application settings API.

Manages a collection of saved AI credentials (``ai_credentials`` table) plus
a singleton ``app_settings`` row that holds which credential is active.
The UI can register multiple keys (e.g. one personal OpenAI key + a shared
gateway token + an Anthropic key) and flip the active one without re-typing.

API keys are write-only — list/detail responses never return the raw key;
they only expose ``hasApiKey`` so the client knows whether something is
stored. Sending ``apiKey`` on create/update saves it; omitting it leaves
the existing key untouched on PATCH.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import AiCredential, AppSettings
from app.schemas.vulnerability import CamelModel

router = APIRouter(prefix="/settings", tags=["settings"])


class CredentialOut(CamelModel):
    id: int
    label: str
    provider: str
    model: str
    base_url: str | None = None
    has_api_key: bool = True
    is_active: bool = False


class CredentialListOut(CamelModel):
    items: list[CredentialOut]
    active_credential_id: int | None = None


class SettingsOut(CamelModel):
    active_credential_id: int | None = None
    active: CredentialOut | None = None


class CredentialCreate(CamelModel):
    label: str = Field(min_length=1, max_length=64)
    provider: str = Field(min_length=1, max_length=32)
    model: str = Field(min_length=1, max_length=64)
    api_key: str = Field(min_length=1)
    base_url: str | None = Field(default=None, max_length=256)
    activate: bool = False


class CredentialUpdate(CamelModel):
    label: str | None = Field(default=None, max_length=64)
    provider: str | None = Field(default=None, max_length=32)
    model: str | None = Field(default=None, max_length=64)
    api_key: str | None = Field(default=None)
    base_url: str | None = Field(default=None, max_length=256)


async def _load_settings_row(db: AsyncSession) -> AppSettings:
    row = (
        await db.execute(select(AppSettings).where(AppSettings.id == 1))
    ).scalar_one_or_none()
    if row is None:
        row = AppSettings(id=1)
        db.add(row)
        await db.flush()
    return row


def _to_out(cred: AiCredential, active_id: int | None) -> CredentialOut:
    return CredentialOut(
        id=cred.id,
        label=cred.label,
        provider=cred.provider,
        model=cred.model,
        base_url=cred.base_url,
        has_api_key=bool(cred.api_key),
        is_active=(active_id is not None and active_id == cred.id),
    )


@router.get("", response_model=SettingsOut, response_model_by_alias=True)
async def get_settings(db: AsyncSession = Depends(get_db)) -> SettingsOut:
    row = await _load_settings_row(db)
    active: CredentialOut | None = None
    if row.active_credential_id is not None:
        cred = (
            await db.execute(
                select(AiCredential).where(AiCredential.id == row.active_credential_id)
            )
        ).scalar_one_or_none()
        if cred is not None:
            active = _to_out(cred, row.active_credential_id)
    return SettingsOut(
        active_credential_id=row.active_credential_id,
        active=active,
    )


@router.get(
    "/credentials",
    response_model=CredentialListOut,
    response_model_by_alias=True,
)
async def list_credentials(db: AsyncSession = Depends(get_db)) -> CredentialListOut:
    row = await _load_settings_row(db)
    items = (
        (await db.execute(select(AiCredential).order_by(AiCredential.created_at)))
        .scalars()
        .all()
    )
    return CredentialListOut(
        items=[_to_out(c, row.active_credential_id) for c in items],
        active_credential_id=row.active_credential_id,
    )


@router.post(
    "/credentials",
    response_model=CredentialOut,
    response_model_by_alias=True,
    status_code=status.HTTP_201_CREATED,
)
async def create_credential(
    body: CredentialCreate,
    db: AsyncSession = Depends(get_db),
) -> CredentialOut:
    cred = AiCredential(
        label=body.label.strip(),
        provider=body.provider.strip().lower(),
        model=body.model.strip(),
        api_key=body.api_key,
        base_url=(body.base_url or "").strip() or None,
    )
    db.add(cred)
    await db.flush()

    settings_row = await _load_settings_row(db)
    # Auto-activate when it's the first credential, or when the caller asks.
    total = (
        await db.execute(select(func.count()).select_from(AiCredential))
    ).scalar_one()
    if body.activate or settings_row.active_credential_id is None or total == 1:
        settings_row.active_credential_id = cred.id

    await db.commit()
    await db.refresh(cred)
    await db.refresh(settings_row)
    return _to_out(cred, settings_row.active_credential_id)


@router.patch(
    "/credentials/{cred_id}",
    response_model=CredentialOut,
    response_model_by_alias=True,
)
async def update_credential(
    cred_id: int,
    body: CredentialUpdate,
    db: AsyncSession = Depends(get_db),
) -> CredentialOut:
    cred = (
        await db.execute(select(AiCredential).where(AiCredential.id == cred_id))
    ).scalar_one_or_none()
    if cred is None:
        raise HTTPException(status_code=404, detail="해당 AI 키를 찾을 수 없습니다.")
    fields = body.model_fields_set
    if "label" in fields and body.label and body.label.strip():
        cred.label = body.label.strip()
    if "provider" in fields and body.provider:
        cred.provider = body.provider.strip().lower()
    if "model" in fields and body.model:
        cred.model = body.model.strip()
    if ("api_key" in fields or "apiKey" in fields) and body.api_key:
        cred.api_key = body.api_key
    if "base_url" in fields or "baseUrl" in fields:
        cleaned = (body.base_url or "").strip()
        cred.base_url = cleaned or None

    settings_row = await _load_settings_row(db)
    await db.commit()
    await db.refresh(cred)
    return _to_out(cred, settings_row.active_credential_id)


@router.delete(
    "/credentials/{cred_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_credential(
    cred_id: int,
    db: AsyncSession = Depends(get_db),
) -> None:
    cred = (
        await db.execute(select(AiCredential).where(AiCredential.id == cred_id))
    ).scalar_one_or_none()
    if cred is None:
        raise HTTPException(status_code=404, detail="해당 AI 키를 찾을 수 없습니다.")
    await db.delete(cred)
    # active_credential_id FK is ON DELETE SET NULL — no extra work needed.
    await db.commit()


@router.post(
    "/credentials/{cred_id}/activate",
    response_model=SettingsOut,
    response_model_by_alias=True,
)
async def activate_credential(
    cred_id: int,
    db: AsyncSession = Depends(get_db),
) -> SettingsOut:
    cred = (
        await db.execute(select(AiCredential).where(AiCredential.id == cred_id))
    ).scalar_one_or_none()
    if cred is None:
        raise HTTPException(status_code=404, detail="해당 AI 키를 찾을 수 없습니다.")
    settings_row = await _load_settings_row(db)
    settings_row.active_credential_id = cred.id
    await db.commit()
    await db.refresh(settings_row)
    return SettingsOut(
        active_credential_id=settings_row.active_credential_id,
        active=_to_out(cred, settings_row.active_credential_id),
    )
