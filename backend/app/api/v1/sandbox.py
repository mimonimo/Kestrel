"""Sandbox API — spawn isolated vulnerability-lab containers, adapt
AI-generated payloads to them, and replay through a single endpoint."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.logging import get_logger
from app.models import LabSourceKind, SandboxSession, SandboxStatus, Vulnerability
from app.schemas.sandbox import (
    AdaptedPayloadOut,
    ExchangeOut,
    InjectionPointOut,
    LabInfoOut,
    RunVerdictOut,
    SandboxExecRequest,
    SandboxExecResponse,
    SandboxSessionOut,
    SandboxStartRequest,
    VulhubSyncResponse,
)
from app.services.ai_analyzer import analyze_vulnerability
from app.services.sandbox import (
    ResolvedLab,
    reap_expired_sessions,
    record_success_payload,
    resolve_lab,
    sync_vulhub,
)
from app.services.sandbox.lab_resolver import LabSpec
from app.services.sandbox.manager import (
    LabImageMissing,
    SandboxError,
    proxy_request,
    reap_expired,
    start_lab,
    stop_lab,
    wait_ready,
)
from app.services.sandbox.payload_adapter import adapt_payload, to_dict

router = APIRouter(prefix="/sandbox", tags=["sandbox"])
log = get_logger(__name__)


def _spec_to_lab_out(spec: LabSpec) -> LabInfoOut:
    return LabInfoOut(
        kind=spec.lab_kind,
        description=spec.description,
        target_path=spec.target_path,
        injection_points=[
            InjectionPointOut(
                name=ip.name,
                method=ip.method,
                path=ip.path,
                parameter=ip.parameter,
                location=ip.location,
                response_kind=ip.response_kind,
                notes=ip.notes,
            )
            for ip in spec.injection_points
        ],
    )


async def _session_to_out(
    db: AsyncSession,
    row: SandboxSession,
    *,
    spec: LabSpec | None = None,
) -> SandboxSessionOut:
    """Build the API view of a session row.

    *spec* is passed in when the caller already resolved one (start/exec).
    For pure GET we re-resolve from the row's CVE so the UI can still show
    the injection-point list — the resolver is cheap (one mapping query).
    """
    lab_out: LabInfoOut | None = None
    if spec is not None:
        lab_out = _spec_to_lab_out(spec)
    elif row.vulnerability_id is not None:
        vuln = await db.scalar(
            select(Vulnerability).where(Vulnerability.id == row.vulnerability_id)
        )
        if vuln is not None:
            resolved = await resolve_lab(db, vuln, forced_kind=row.lab_kind)
            if resolved is not None:
                lab_out = _spec_to_lab_out(resolved.spec)

    return SandboxSessionOut(
        id=row.id,
        vulnerability_id=row.vulnerability_id,
        lab_kind=row.lab_kind,
        lab_source=row.lab_source,
        verified=row.verified,
        container_name=row.container_name,
        target_url=row.target_url,
        status=row.status,
        error=row.error,
        last_run=row.last_run,
        created_at=row.created_at,
        expires_at=row.expires_at,
        lab=lab_out,
    )


async def _count_running(db: AsyncSession) -> int:
    return (
        await db.execute(
            select(func.count())
            .select_from(SandboxSession)
            .where(SandboxSession.status == SandboxStatus.RUNNING)
        )
    ).scalar_one()


@router.post(
    "/vulhub/sync",
    response_model=VulhubSyncResponse,
    response_model_by_alias=True,
)
async def vulhub_sync(db: AsyncSession = Depends(get_db)) -> VulhubSyncResponse:
    """Pull the vulhub repo and (re)build all ``vulhub``-kind mappings.

    No AI calls. Safe to run repeatedly — the harvester only writes to a row
    when its ``lab_kind`` or ``spec`` actually changed. First call fresh-clones
    the repo (long); subsequent calls fast-forward.
    """
    try:
        stats = await sync_vulhub(db)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    return VulhubSyncResponse(
        folders_scanned=stats.folders_scanned,
        candidates=stats.candidates,
        upserted=stats.upserted,
        skipped=stats.skipped,
        errors=stats.errors[:50],  # cap so we don't return megabytes
    )


@router.post(
    "/sessions",
    response_model=SandboxSessionOut,
    response_model_by_alias=True,
    status_code=status.HTTP_201_CREATED,
)
async def start_session(
    body: SandboxStartRequest, db: AsyncSession = Depends(get_db)
) -> SandboxSessionOut:
    settings = get_settings()
    # Opportunistic reap of stale containers — keeps capacity honest without
    # needing a separate scheduler job. Two paths: label-driven reap covers
    # image-mode containers; DB-driven reap covers compose stacks (where we
    # can't add labels post-creation).
    await reap_expired()
    await reap_expired_sessions(db)

    vuln = await db.scalar(
        select(Vulnerability).where(Vulnerability.cve_id == body.cve_id)
    )
    if vuln is None:
        raise HTTPException(status_code=404, detail=f"{body.cve_id} not found")

    forced = (body.lab_kind or "").strip().lower() or None
    resolved = await resolve_lab(db, vuln, forced_kind=forced)
    if resolved is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "이 CVE에 대응하는 샌드박스 랩이 아직 없습니다. "
                "현재 지원: 일반 클래스 lab(XSS) + 사전 등록된 vulhub 매핑. "
                "추후 PR에서 vulhub 시드 + AI 합성으로 커버리지를 확장합니다."
            ),
        )

    running = await _count_running(db)
    if running >= settings.sandbox_max_concurrent:
        raise HTTPException(
            status_code=429,
            detail=(
                f"동시 실행 가능한 샌드박스 수({settings.sandbox_max_concurrent})를 초과했습니다. "
                "기존 세션을 정지한 뒤 다시 시도하세요."
            ),
        )

    session_row = SandboxSession(
        vulnerability_id=vuln.id,
        lab_kind=resolved.spec.lab_kind,
        lab_source=resolved.source,
        verified=resolved.verified,
        status=SandboxStatus.PENDING,
    )
    db.add(session_row)
    await db.flush()  # populate session_row.id

    try:
        handle = await start_lab(resolved.spec, session_row.id)
        await wait_ready(handle.target_url, resolved.spec)
    except LabImageMissing as e:
        session_row.status = SandboxStatus.FAILED
        session_row.error = str(e)
        await db.commit()
        raise HTTPException(status_code=503, detail=str(e)) from e
    except SandboxError as e:
        session_row.status = SandboxStatus.FAILED
        session_row.error = str(e)
        await db.commit()
        # Best-effort cleanup of any partially-created container or compose
        # stack.
        cleanup_handle = session_row.container_id or session_row.container_name
        if cleanup_handle:
            await stop_lab(cleanup_handle)
        raise HTTPException(status_code=502, detail=str(e)) from e

    session_row.status = SandboxStatus.RUNNING
    session_row.container_id = handle.container_id
    session_row.container_name = handle.container_name
    session_row.target_url = handle.target_url
    session_row.expires_at = handle.expires_at
    await db.commit()
    await db.refresh(session_row)
    return await _session_to_out(db, session_row, spec=resolved.spec)


@router.get(
    "/sessions/{session_id}",
    response_model=SandboxSessionOut,
    response_model_by_alias=True,
)
async def get_session(
    session_id: UUID, db: AsyncSession = Depends(get_db)
) -> SandboxSessionOut:
    row = await db.scalar(
        select(SandboxSession).where(SandboxSession.id == session_id)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    # Surface TTL expiry to the client even if the reaper hasn't run yet.
    if (
        row.status == SandboxStatus.RUNNING
        and row.expires_at is not None
        and row.expires_at <= datetime.now(timezone.utc)
    ):
        row.status = SandboxStatus.EXPIRED
        await db.commit()
    return await _session_to_out(db, row)


@router.delete(
    "/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def stop_session(
    session_id: UUID, db: AsyncSession = Depends(get_db)
) -> None:
    row = await db.scalar(
        select(SandboxSession).where(SandboxSession.id == session_id)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    # ``container_id`` is the *handle* the manager hands back: image-mode
    # stores the container name; compose-mode stores the project name. Pass
    # it straight through so stop_lab can route to the correct teardown.
    handle = row.container_id or row.container_name
    if handle:
        await stop_lab(handle)
    row.status = SandboxStatus.STOPPED
    await db.commit()


@router.post(
    "/sessions/{session_id}/exec",
    response_model=SandboxExecResponse,
    response_model_by_alias=True,
)
async def exec_payload(
    session_id: UUID,
    body: SandboxExecRequest,
    db: AsyncSession = Depends(get_db),
) -> SandboxExecResponse:
    row = await db.scalar(
        select(SandboxSession).where(SandboxSession.id == session_id)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    if row.status != SandboxStatus.RUNNING or not row.target_url:
        raise HTTPException(
            status_code=409,
            detail=f"세션 상태가 실행 중이 아닙니다 (현재: {row.status.value}).",
        )

    vuln: Vulnerability | None = None
    if row.vulnerability_id is not None:
        vuln = await db.scalar(
            select(Vulnerability).where(Vulnerability.id == row.vulnerability_id)
        )
    if vuln is None:
        raise HTTPException(
            status_code=409,
            detail="이 세션에 연결된 CVE 정보를 찾을 수 없습니다.",
        )

    resolved = await resolve_lab(db, vuln, forced_kind=row.lab_kind)
    if resolved is None:
        raise HTTPException(
            status_code=500,
            detail=f"세션 시작 시 매핑되었던 lab을 찾을 수 없습니다: {row.lab_kind}",
        )

    # Decide whether to use the cached payload. The cache is keyed on
    # (cve, lab) so swapping out the generic_payload only matters when the
    # caller asks us to regenerate.
    force_regen = bool(body.force_regenerate)
    cached = None if force_regen else resolved.cached_payload

    generic = (body.generic_payload or "").strip()
    if not generic and cached is None:
        # Only spend tokens on the analyzer when we actually need fresh input.
        analysis = await analyze_vulnerability(db, vuln)
        generic = analysis.payload_example

    adapted = await adapt_payload(
        db,
        cve_id=vuln.cve_id,
        title=vuln.title,
        description=vuln.description,
        generic_payload=generic,
        target_url=row.target_url,
        spec=resolved.spec,
        cached_payload=cached,
        force_regenerate=force_regen,
    )

    # Build the actual HTTP request based on adapted.location
    params: dict[str, str] | None = None
    data: dict[str, str] | None = None
    json_body: dict | None = None
    headers: dict[str, str] | None = None
    if adapted.location == "form":
        data = {adapted.parameter: adapted.payload}
    elif adapted.location == "json":
        json_body = {adapted.parameter: adapted.payload}
    elif adapted.location == "header":
        headers = {adapted.parameter: adapted.payload}
    else:  # default: query
        params = {adapted.parameter: adapted.payload}

    try:
        exchange = await proxy_request(
            row.target_url,
            adapted.method,
            adapted.path,
            params=params,
            data=data,
            json=json_body,
            headers=headers,
        )
    except SandboxError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e

    # Lazy import to avoid pulling result_analyzer (and the LLM client) at
    # module import time.
    from app.services.sandbox.result_analyzer import analyze_run

    verdict = await analyze_run(
        db,
        cve_id=vuln.cve_id,
        title=vuln.title,
        lab_kind=row.lab_kind,
        adapted=adapted,
        exchange=exchange,
    )

    # On a successful run, cache the working payload so the next exec for
    # this same (CVE, lab) combo skips the LLM call. Update verified flag
    # on the session too — the UI badge should reflect the current state.
    if verdict.success and not adapted.from_cache:
        try:
            await record_success_payload(
                db,
                cve_id=vuln.cve_id,
                resolved=resolved,
                adapted_payload_dict=to_dict(adapted),
            )
            row.verified = True
        except Exception as e:  # cache is best-effort; never fail the request
            log.warning("sandbox.cache_write_failed", error=str(e))

    row.last_run = {
        "adapted": {**to_dict(adapted), "from_cache": adapted.from_cache},
        "exchange": exchange,
        "verdict": {
            "success": verdict.success,
            "confidence": verdict.confidence,
            "summary": verdict.summary,
            "evidence": verdict.evidence,
            "next_step": verdict.next_step,
            "heuristic_signal": verdict.heuristic_signal,
        },
        "ran_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.commit()
    await db.refresh(row)

    return SandboxExecResponse(
        session=await _session_to_out(db, row, spec=resolved.spec),
        adapted=AdaptedPayloadOut(
            method=adapted.method,
            path=adapted.path,
            parameter=adapted.parameter,
            location=adapted.location,
            payload=adapted.payload,
            success_indicator=adapted.success_indicator,
            rationale=adapted.rationale,
            notes=adapted.notes,
            from_cache=adapted.from_cache,
        ),
        exchange=ExchangeOut(**exchange),
        verdict=RunVerdictOut(
            success=verdict.success,
            confidence=verdict.confidence,
            summary=verdict.summary,
            evidence=verdict.evidence,
            next_step=verdict.next_step,
            heuristic_signal=verdict.heuristic_signal,
        ),
    )
