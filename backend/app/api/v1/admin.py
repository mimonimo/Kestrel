"""Operator endpoints — manual ingestion triggers with per-request key overrides.

The frontend settings page POSTs saved NVD / GitHub keys here so the user can
validate them with a fresh pull. Keys are used for the duration of the request
only; they are never written to the DB or env.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, BackgroundTasks, Depends, Header
from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pydantic import BaseModel as _PydBaseModel
from pydantic import ConfigDict as _PydConfigDict

from app.api.v1.deps import require_admin
from app.core.database import SessionLocal, get_db
from app.core.logging import get_logger
from app.models import AppSettings
from app.services.ingestion import run_parser
from app.services.parsers import ExploitDbParser, GithubAdvisoryParser, NvdParser
from app.services.parsers.mitre import MitreParser
from app.services.priority_signals import refresh_all as refresh_priority_signals

log = get_logger(__name__)

# 전체 router 에 admin 가드 — refresh / priority-signals / mitre-backfill
# 등 운영 명령은 모두 관리자만 호출. 일반 유저는 401/403.
router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])


# ─── 외부 데이터 소스 키 관리 (PR 10-CQ) ─────────────────────────────
# 응답에는 마스킹된 값만 (`****1234`) 노출. PUT 으로 저장.
# admin 본인이 웹 UI 에서 한 곳에서 관리 — 어디서 접속해도 같은 상태.


def _mask(value: str | None) -> str | None:
    if not value:
        return None
    tail = value[-4:] if len(value) >= 4 else value
    return f"****{tail}"


class _ExternalKeysCamel(_PydBaseModel):
    model_config = _PydConfigDict(alias_generator=lambda s: "".join(
        [s.split("_")[0]] + [w.capitalize() for w in s.split("_")[1:]]
    ), populate_by_name=True)


class ExternalKeysOut(_ExternalKeysCamel):
    nvd_api_key: str | None = None
    github_token: str | None = None
    nvd_set: bool = False
    github_set: bool = False


class ExternalKeysUpdate(_ExternalKeysCamel):
    # ``None`` = 변경 안 함. 빈 문자열 = 삭제. 비-공백 문자열 = 새 값.
    nvd_api_key: str | None = None
    github_token: str | None = None


@router.get(
    "/external-keys",
    response_model=ExternalKeysOut,
    response_model_by_alias=True,
)
async def get_external_keys(db: AsyncSession = Depends(get_db)) -> ExternalKeysOut:
    row = await db.scalar(select(AppSettings).where(AppSettings.id == 1))
    nvd = row.nvd_api_key if row else None
    gh = row.github_token if row else None
    return ExternalKeysOut(
        nvd_api_key=_mask(nvd),
        github_token=_mask(gh),
        nvd_set=bool(nvd),
        github_set=bool(gh),
    )


@router.put(
    "/external-keys",
    response_model=ExternalKeysOut,
    response_model_by_alias=True,
)
async def put_external_keys(
    body: ExternalKeysUpdate, db: AsyncSession = Depends(get_db)
) -> ExternalKeysOut:
    row = await db.scalar(select(AppSettings).where(AppSettings.id == 1))
    if row is None:
        row = AppSettings(id=1)
        db.add(row)
    fields = body.model_fields_set
    actions: list[str] = []
    if "nvd_api_key" in fields or "nvdApiKey" in fields:
        new_val = (body.nvd_api_key or "").strip()
        if new_val:
            row.nvd_api_key = new_val
            actions.append("nvd_set")
        else:
            row.nvd_api_key = None
            actions.append("nvd_cleared")
    if "github_token" in fields or "githubToken" in fields:
        new_val = (body.github_token or "").strip()
        if new_val:
            row.github_token = new_val
            actions.append("gh_set")
        else:
            row.github_token = None
            actions.append("gh_cleared")
    await db.commit()
    # 토큰 자체는 로깅 X — 누가 어떤 액션을 했는지만.
    if actions:
        log.info("admin.external_keys_updated", actions=actions)
    return await get_external_keys(db)


@router.post("/refresh")
async def refresh_ingestion(
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    x_nvd_api_key: str | None = Header(default=None, alias="X-NVD-API-Key"),
    x_github_token: str | None = Header(default=None, alias="X-GitHub-Token"),
    full_resync: str | None = Header(default=None, alias="X-Full-Resync"),
) -> dict:
    """Kick off one ingestion run per source, using the provided keys if any.

    Runs in the background so the HTTP call returns immediately — the caller
    should poll ``/status`` to see each source's latest log row update.

    PR 10-AJ: when keys are provided, persist them to ``app_settings`` so
    the background scheduler also uses them on subsequent ticks (previously
    only this-request was authenticated; scheduler ran token-less and GHSA
    returned 0 rows).

    ``X-Full-Resync: ghsa`` (or ``all``) bypasses the per-source
    ``last_success`` watermark so the parser walks from its natural
    beginning again. Use this to recover from a since-window gap — when
    earlier runs returned 0 items due to a transient token issue,
    ``finished_at`` advanced past advisories that were never actually
    fetched.
    """
    row = await db.scalar(select(AppSettings).where(AppSettings.id == 1))
    if x_nvd_api_key or x_github_token:
        if row is None:
            row = AppSettings(id=1)
            db.add(row)
        if x_nvd_api_key:
            row.nvd_api_key = x_nvd_api_key
        if x_github_token:
            row.github_token = x_github_token
        await db.commit()

    # Fall back to persisted keys when the caller didn't send headers —
    # the scheduler already does this (jobs._resolve_external_keys), so
    # without this fallback "전체 다시 받기" from a device without the
    # key in localStorage runs token-less and fails the same way the
    # original since-window gap was caused.
    nvd_token = x_nvd_api_key or (row.nvd_api_key if row else None)
    gh_token = x_github_token or (row.github_token if row else None)

    resync_tokens = {t.strip().lower() for t in (full_resync or "").split(",") if t.strip()}
    ghsa_full = "ghsa" in resync_tokens or "all" in resync_tokens
    nvd_full = "nvd" in resync_tokens or "all" in resync_tokens
    edb_full = "exploit_db" in resync_tokens or "all" in resync_tokens

    async def _run_all() -> None:
        await asyncio.gather(
            run_parser(NvdParser(api_key_override=nvd_token), full_resync=nvd_full),
            run_parser(
                GithubAdvisoryParser(token_override=gh_token),
                full_resync=ghsa_full,
            ),
            run_parser(ExploitDbParser(), full_resync=edb_full),
            return_exceptions=True,
        )

    background.add_task(_run_all)
    return {
        "queued": True,
        "usedKeys": {
            "nvd": bool(nvd_token),
            "github": bool(gh_token),
        },
        "fullResync": {
            "nvd": nvd_full,
            "ghsa": ghsa_full,
            "exploit_db": edb_full,
        },
    }


@router.post("/refresh-priority-signals")
async def refresh_priority_signals_endpoint(background: BackgroundTasks) -> dict:
    """Pull the current CISA KEV catalog + FIRST EPSS snapshot and update
    matching CVE rows. Runs in the background — poll the same row from
    /dashboard/insights to see counts move."""
    background.add_task(refresh_priority_signals)
    return {"queued": True}


class _CamelOut(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class MitreBackfillRequest(_CamelOut):
    # 'full' walks every CVE JSON in the repo (~340k); 'delta' only files
    # touched by git in the last ``since_days``.
    mode: str = Field(default="delta", pattern="^(full|delta)$")
    since_days: int = Field(default=14, ge=1, le=365)
    # Cap for safety / progress dry-runs. ``None`` = no cap.
    max_records: int | None = Field(default=None, ge=1, le=400_000)


class MitreBackfillResponse(_CamelOut):
    queued: bool
    mode: str
    detail: str


@router.post(
    "/mitre-backfill",
    response_model=MitreBackfillResponse,
    response_model_by_alias=True,
)
async def mitre_backfill(
    body: MitreBackfillRequest, background: BackgroundTasks
) -> MitreBackfillResponse:
    """Trigger a one-shot MITRE cvelistV5 ingestion.

    Full mode covers ~340k records and takes 30-60+ min on first run
    (mostly the initial git clone of ~5GB). Delta mode catches up the
    last ``since_days`` of changes — typical daily run, finishes in
    under a minute after the repo exists.

    Background task — caller polls ``/status`` for ``mitre`` row.
    """

    async def _run() -> None:
        try:
            await run_parser(
                MitreParser(
                    mode=body.mode,
                    since_days=body.since_days,
                    max_records=body.max_records,
                )
            )
        except Exception:
            log.exception("admin.mitre_backfill_failed")

    background.add_task(_run)
    detail = (
        f"MITRE {body.mode} 백필을 백그라운드에서 시작했습니다. "
        f"진행 상황은 /status 의 mitre 행으로 확인하세요. "
    )
    if body.mode == "full":
        detail += "(첫 실행 시 git clone ~5GB + 340k 행 처리, 30~60분 소요)"
    else:
        detail += f"(최근 {body.since_days}일 델타만 처리)"
    return MitreBackfillResponse(queued=True, mode=body.mode, detail=detail)
