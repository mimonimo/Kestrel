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
from app.models import SandboxSession, SandboxStatus, Vulnerability
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
)
from app.services.ai_analyzer import analyze_vulnerability
from app.services.sandbox import classify_vulnerability, get_lab
from app.services.sandbox.manager import (
    LabImageMissing,
    SandboxError,
    proxy_request,
    reap_expired,
    start_lab,
    stop_lab,
    wait_ready,
)
from app.services.sandbox.payload_adapter import adapt_payload
from app.services.sandbox.result_analyzer import analyze_run

router = APIRouter(prefix="/sandbox", tags=["sandbox"])
log = get_logger(__name__)


def _lab_to_out(lab) -> LabInfoOut:
    return LabInfoOut(
        kind=lab.kind,
        description=lab.description,
        target_path=lab.target_path,
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
            for ip in lab.injection_points
        ],
    )


def _session_to_out(row: SandboxSession, include_lab: bool = True) -> SandboxSessionOut:
    lab_out: LabInfoOut | None = None
    if include_lab:
        lab = get_lab(row.lab_kind)
        if lab is not None:
            lab_out = _lab_to_out(lab)
    return SandboxSessionOut(
        id=row.id,
        vulnerability_id=row.vulnerability_id,
        lab_kind=row.lab_kind,
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
    # needing a separate scheduler job.
    await reap_expired()

    vuln = await db.scalar(
        select(Vulnerability).where(Vulnerability.cve_id == body.cve_id)
    )
    if vuln is None:
        raise HTTPException(status_code=404, detail=f"{body.cve_id} not found")

    kind = (body.lab_kind or "").strip().lower() or classify_vulnerability(vuln)
    if not kind:
        raise HTTPException(
            status_code=400,
            detail=(
                "이 CVE에 대응하는 샌드박스 랩이 아직 없습니다. "
                "현재 지원: XSS. 다른 클래스는 점진적으로 추가 예정입니다."
            ),
        )
    lab = get_lab(kind)
    if lab is None:
        raise HTTPException(status_code=400, detail=f"알 수 없는 lab 종류: {kind}")

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
        lab_kind=kind,
        status=SandboxStatus.PENDING,
    )
    db.add(session_row)
    await db.flush()  # populate session_row.id

    try:
        handle = await start_lab(lab, session_row.id)
        await wait_ready(handle.target_url, lab)
    except LabImageMissing as e:
        session_row.status = SandboxStatus.FAILED
        session_row.error = str(e)
        await db.commit()
        raise HTTPException(status_code=503, detail=str(e)) from e
    except SandboxError as e:
        session_row.status = SandboxStatus.FAILED
        session_row.error = str(e)
        await db.commit()
        # Best-effort cleanup of any partially-created container.
        if session_row.container_name:
            await stop_lab(session_row.container_name)
        raise HTTPException(status_code=502, detail=str(e)) from e

    session_row.status = SandboxStatus.RUNNING
    session_row.container_id = handle.container_id
    session_row.container_name = handle.container_name
    session_row.target_url = handle.target_url
    session_row.expires_at = handle.expires_at
    await db.commit()
    await db.refresh(session_row)
    return _session_to_out(session_row)


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
    return _session_to_out(row)


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
    if row.container_name:
        await stop_lab(row.container_name)
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
    lab = get_lab(row.lab_kind)
    if lab is None:
        raise HTTPException(status_code=500, detail=f"lab 정의가 사라졌습니다: {row.lab_kind}")

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

    # Get a generic payload to start from. Caller can pass one (e.g. the AI
    # analysis result they already have on screen); otherwise we generate a
    # fresh one via the standard analyzer prompt.
    generic = (body.generic_payload or "").strip()
    if not generic:
        analysis = await analyze_vulnerability(db, vuln)
        generic = analysis.payload_example

    adapted = await adapt_payload(
        db,
        cve_id=vuln.cve_id,
        title=vuln.title,
        description=vuln.description,
        generic_payload=generic,
        target_url=row.target_url,
        lab=lab,
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

    verdict = await analyze_run(
        db,
        cve_id=vuln.cve_id,
        title=vuln.title,
        lab_kind=row.lab_kind,
        adapted=adapted,
        exchange=exchange,
    )

    row.last_run = {
        "adapted": {
            "method": adapted.method,
            "path": adapted.path,
            "parameter": adapted.parameter,
            "location": adapted.location,
            "payload": adapted.payload,
            "success_indicator": adapted.success_indicator,
            "rationale": adapted.rationale,
            "notes": adapted.notes,
        },
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
        session=_session_to_out(row),
        adapted=AdaptedPayloadOut(
            method=adapted.method,
            path=adapted.path,
            parameter=adapted.parameter,
            location=adapted.location,
            payload=adapted.payload,
            success_indicator=adapted.success_indicator,
            rationale=adapted.rationale,
            notes=adapted.notes,
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
