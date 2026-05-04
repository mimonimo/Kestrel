"""Sandbox API — spawn isolated vulnerability-lab containers, adapt
AI-generated payloads to them, and replay through a single endpoint."""
from __future__ import annotations

import asyncio
import json as _json
from datetime import datetime, timezone
from typing import AsyncIterator
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.logging import get_logger
from app.models import (
    CveLabFeedback,
    CveLabMapping,
    LabSourceKind,
    SandboxSession,
    SandboxStatus,
    Vulnerability,
)
from app.schemas.sandbox import (
    AdaptedPayloadOut,
    EvictedImageOut,
    ExchangeOut,
    InjectionPointOut,
    LabFeedbackRequest,
    LabFeedbackResponse,
    LabInfoOut,
    RunVerdictOut,
    SandboxExecRequest,
    SandboxExecResponse,
    SandboxSessionOut,
    SandboxStartRequest,
    LabKindStatsBucket,
    LabKindStatsReport,
    SynthCandidateOut,
    SynthCandidatesResponse,
    SynthesizeCacheEntryOut,
    SynthesizeCacheReport,
    SynthesizeGcRequest,
    SynthesizeGcResponse,
    SynthesizeRequest,
    SynthesizeResponse,
    VulhubSyncResponse,
)
from app.services.ai_analyzer import analyze_vulnerability
from app.services.sandbox import (
    ResolvedLab,
    gc_synthesized_images,
    reap_expired_sessions,
    record_success_payload,
    report_synthesized_cache,
    resolve_lab,
    synthesize,
    sync_vulhub,
)
from app.services.sandbox.lab_resolver import (
    LabSpec,
    _spec_from_mapping,
    is_degraded,
    list_synthesized_candidates,
    report_lab_kind_distribution,
)
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


def _spec_to_lab_out(
    spec: LabSpec,
    *,
    my_vote: str | None = None,
    degraded: bool = False,
    candidate_count: int = 0,
    candidate_rank: int = 0,
) -> LabInfoOut:
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
        digest=spec.digest,
        feedback_up=spec.feedback_up,
        feedback_down=spec.feedback_down,
        my_vote=my_vote,
        degraded=degraded,
        candidate_count=candidate_count,
        candidate_rank=candidate_rank,
    )


async def _candidate_position(
    db: AsyncSession, cve_id: str, mapping_id: int | None
) -> tuple[int, int]:
    """Return ``(rank, total)`` of a synthesized mapping among its CVE's
    candidates. (0, 0) for non-synthesized labs or when the mapping isn't
    in the candidate list."""
    if mapping_id is None or not cve_id:
        return 0, 0
    candidates = await list_synthesized_candidates(db, cve_id)
    if not candidates:
        return 0, 0
    for i, m in enumerate(candidates, start=1):
        if m.id == mapping_id:
            return i, len(candidates)
    return 0, len(candidates)


async def _my_vote(
    db: AsyncSession, mapping_id: int | None, client_id: str | None
) -> str | None:
    """Look up the caller's vote on a mapping, if any. Returns None when
    no client_id was supplied or no vote row exists."""
    if mapping_id is None or not client_id:
        return None
    fb = await db.scalar(
        select(CveLabFeedback).where(
            CveLabFeedback.mapping_id == mapping_id,
            CveLabFeedback.client_id == client_id,
        )
    )
    return fb.vote if fb is not None else None


def _degraded_from_counts(up: int, down: int) -> bool:
    """Mirror of resolver.is_degraded that works from raw counts. Used
    when surfacing a session whose mapping would *now* be degraded —
    even though the resolver let it through earlier (e.g. user voted it
    down after starting the session)."""
    return down >= 2 and down >= up + 2


async def _session_to_out(
    db: AsyncSession,
    row: SandboxSession,
    *,
    spec: LabSpec | None = None,
    mapping_id: int | None = None,
    client_id: str | None = None,
) -> SandboxSessionOut:
    """Build the API view of a session row.

    *spec* is passed in when the caller already resolved one (start/exec).
    For pure GET we re-resolve from the row's CVE so the UI can still show
    the injection-point list — the resolver is cheap (one mapping query).
    """
    lab_out: LabInfoOut | None = None
    effective_mapping_id: int | None = mapping_id
    if spec is not None:
        my_vote = await _my_vote(db, mapping_id, client_id)
        degraded = _degraded_from_counts(spec.feedback_up, spec.feedback_down)
        cve_id_for_pos = (
            (await db.scalar(select(Vulnerability.cve_id).where(Vulnerability.id == row.vulnerability_id)))
            if row.vulnerability_id is not None
            else ""
        )
        rank, total = await _candidate_position(db, cve_id_for_pos or "", mapping_id)
        lab_out = _spec_to_lab_out(
            spec, my_vote=my_vote, degraded=degraded,
            candidate_count=total, candidate_rank=rank,
        )
    elif row.vulnerability_id is not None:
        vuln = await db.scalar(
            select(Vulnerability).where(Vulnerability.id == row.vulnerability_id)
        )
        if vuln is not None:
            resolved = await resolve_lab(db, vuln, forced_kind=row.lab_kind)
            if resolved is not None:
                effective_mapping_id = resolved.mapping_id
                my_vote = await _my_vote(db, resolved.mapping_id, client_id)
                degraded = _degraded_from_counts(
                    resolved.spec.feedback_up, resolved.spec.feedback_down
                )
                rank, total = await _candidate_position(
                    db, vuln.cve_id, resolved.mapping_id
                )
                lab_out = _spec_to_lab_out(
                    resolved.spec, my_vote=my_vote, degraded=degraded,
                    candidate_count=total, candidate_rank=rank,
                )
            else:
                # Resolver refused (e.g. synthesized mapping was degraded
                # after the session started). Fall back to a direct mapping
                # lookup so the panel can still render the lab info + the
                # degraded badge — the session is alive, the user wants to
                # see what it's running.
                mapping = await db.scalar(
                    select(CveLabMapping).where(
                        CveLabMapping.cve_id == vuln.cve_id,
                        CveLabMapping.kind == row.lab_source,
                    )
                )
                if mapping is not None:
                    effective_mapping_id = mapping.id
                    fallback_spec = _spec_from_mapping(mapping)
                    my_vote = await _my_vote(db, mapping.id, client_id)
                    degraded = _degraded_from_counts(
                        fallback_spec.feedback_up, fallback_spec.feedback_down
                    )
                    rank, total = await _candidate_position(
                        db, vuln.cve_id, mapping.id
                    )
                    lab_out = _spec_to_lab_out(
                        fallback_spec, my_vote=my_vote, degraded=degraded,
                        candidate_count=total, candidate_rank=rank,
                    )

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
        mapping_id=effective_mapping_id,
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
    "/synthesize",
    response_model=SynthesizeResponse,
    response_model_by_alias=True,
)
async def synthesize_lab(
    body: SynthesizeRequest, db: AsyncSession = Depends(get_db)
) -> SynthesizeResponse:
    """AI-synthesize a lab for *cve_id* and verify it.

    On success, the resulting ``cve_lab_mappings(kind=synthesized)`` row is
    visible to the resolver chain and future sandbox sessions for this CVE
    will use it automatically (vulhub still wins if both exist).

    Failures (LLM error, build error, indicator missing in response) return
    HTTP 200 with ``verified=false`` and an ``error`` string — the caller can
    inspect ``buildLogTail`` / ``responseBodyPreview`` to decide whether to
    retry. We deliberately do not raise so the UI can render the diagnostics.
    """
    vuln = await db.scalar(
        select(Vulnerability).where(Vulnerability.cve_id == body.cve_id)
    )
    if vuln is None:
        raise HTTPException(status_code=404, detail=f"{body.cve_id} not found")

    result = await synthesize(db, vuln, force_regenerate=body.force_regenerate)
    return SynthesizeResponse(
        cve_id=result.cve_id,
        image_tag=result.image_tag,
        verified=result.verified,
        mapping_id=result.mapping_id,
        attempts=result.attempts,
        error=result.error,
        spec=result.spec_dict,
        payload=result.payload,
        build_log_tail=result.build_log_tail,
        response_status=result.response_status,
        response_body_preview=result.response_body_preview,
    )


def _sse_chunk(event: str, data: dict) -> bytes:
    """Format one Server-Sent Event frame.

    Lines must be \\n-separated and the frame ends with a blank line. We
    encode JSON as a single ``data:`` line — the spec allows multiple but
    one keeps the parser trivial on the browser side.
    """
    payload = _json.dumps(data, ensure_ascii=False, default=str)
    return f"event: {event}\ndata: {payload}\n\n".encode("utf-8")


@router.post("/synthesize/stream")
async def synthesize_stream(
    body: SynthesizeRequest, db: AsyncSession = Depends(get_db)
) -> StreamingResponse:
    """SSE stream of synthesis progress.

    Each ``step`` event carries ``{phase, message, payload}`` keyed to the
    stages in synthesizer.synthesize. The final ``done`` event carries the
    full SynthesisResult (same shape as the non-streaming endpoint's body).
    Connection errors mid-stream do NOT abort synthesis — the call already
    spent LLM tokens by then so we let it finish writing the DB row and the
    image cache.
    """
    vuln = await db.scalar(
        select(Vulnerability).where(Vulnerability.cve_id == body.cve_id)
    )
    if vuln is None:
        raise HTTPException(status_code=404, detail=f"{body.cve_id} not found")

    queue: asyncio.Queue[bytes | None] = asyncio.Queue()

    async def emit(phase: str, message: str, payload: dict | None) -> None:
        await queue.put(
            _sse_chunk("step", {"phase": phase, "message": message, "payload": payload})
        )

    async def runner() -> None:
        try:
            result = await synthesize(
                db,
                vuln,
                force_regenerate=body.force_regenerate,
                progress=emit,
            )
            done = {
                "cveId": result.cve_id,
                "imageTag": result.image_tag,
                "verified": result.verified,
                "mappingId": result.mapping_id,
                "attempts": result.attempts,
                "error": result.error,
                "spec": result.spec_dict,
                "payload": result.payload,
                "buildLogTail": result.build_log_tail,
                "responseStatus": result.response_status,
                "responseBodyPreview": result.response_body_preview,
            }
            await queue.put(_sse_chunk("done", done))
        except Exception as e:  # noqa: BLE001 — last resort, surface to client
            log.warning("synthesize_stream.unhandled", error=str(e))
            await queue.put(_sse_chunk("error", {"message": str(e)}))
        finally:
            await queue.put(None)  # sentinel — close the stream

    task = asyncio.create_task(runner())

    async def gen() -> AsyncIterator[bytes]:
        try:
            while True:
                chunk = await queue.get()
                if chunk is None:
                    return
                yield chunk
        finally:
            # Client disconnected before runner finished — let it complete
            # in the background (we already burned LLM tokens, may as well
            # cache the result on success).
            if not task.done():
                log.info("synthesize_stream.client_disconnect", cve_id=body.cve_id)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",  # disables nginx buffering if proxied
        },
    )


@router.get(
    "/synthesize/cache",
    response_model=SynthesizeCacheReport,
    response_model_by_alias=True,
)
async def synthesize_cache(
    db: AsyncSession = Depends(get_db),
) -> SynthesizeCacheReport:
    """Read-only snapshot of the synthesized-image cache.

    Drives the operator dashboard. Entries are sorted oldest-LRU first so
    the UI can show what the next GC sweep would evict. Includes the
    configured ceilings so the panel can render utilization without a
    separate /settings round-trip.
    """
    settings = get_settings()
    report = await report_synthesized_cache(db)
    return SynthesizeCacheReport(
        count=report.count,
        total_mb=report.total_mb,
        in_use_count=report.in_use_count,
        missing_image_count=report.missing_image_count,
        oldest_last_used_at=report.oldest_last_used_at,
        max_total_mb=settings.sandbox_syn_image_max_total_mb,
        max_count=settings.sandbox_syn_image_max_count,
        max_age_days=settings.sandbox_syn_image_max_age_days,
        entries=[
            SynthesizeCacheEntryOut(
                cve_id=e.cve_id,
                image_tag=e.image_tag,
                lab_kind=e.lab_kind,
                size_mb=e.size_mb,
                in_use=e.in_use,
                image_present=e.image_present,
                last_used_at=e.last_used_at,
                last_verified_at=e.last_verified_at,
                created_at=e.created_at,
                age_days=e.age_days,
            )
            for e in report.entries
        ],
    )


@router.get(
    "/cves/{cve_id}/synth-candidates",
    response_model=SynthCandidatesResponse,
    response_model_by_alias=True,
)
async def synth_candidates(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
) -> SynthCandidatesResponse:
    """List synthesized candidate mappings for *cve_id*, score-ordered.

    Drives the manual candidate pivot UI (PR 9-U) — operators see all
    candidates side by side and can pin a non-default one to the next
    sandbox session via SandboxStartRequest.mapping_id.

    Includes the cooldown placeholder (verified=False, lab_kind ends
    with '/pending') so the operator can also see "synthesis was
    attempted but failed" rows. UI hides them under is_placeholder.
    """
    rows = await list_synthesized_candidates(db, cve_id)
    candidates: list[SynthCandidateOut] = []
    for i, m in enumerate(rows, start=1):
        candidates.append(
            SynthCandidateOut(
                mapping_id=m.id,
                rank=i,
                lab_kind=m.lab_kind,
                digest=str((m.spec or {}).get("digest", "")),
                verified=bool(m.verified),
                feedback_up=int(m.feedback_up or 0),
                feedback_down=int(m.feedback_down or 0),
                degraded=is_degraded(m),
                last_verified_at=m.last_verified_at,
                created_at=m.created_at,
                is_placeholder=str(m.lab_kind).endswith("/pending"),
            )
        )
    return SynthCandidatesResponse(cve_id=cve_id, candidates=candidates)


@router.get(
    "/lab-kind-stats",
    response_model=LabKindStatsReport,
    response_model_by_alias=True,
)
async def lab_kind_stats(
    db: AsyncSession = Depends(get_db),
) -> LabKindStatsReport:
    """Read-only distribution of cve_lab_mappings rows by source/lab kind.

    Drives the operator dashboard panel that surfaces the effect of the
    prompt-debias work (PR 9-N) and generic-catalog expansion (PR 9-O).
    If XSS-bias regresses, by_kind shows it as a single dominant bucket.
    """
    stats = await report_lab_kind_distribution(db)
    return LabKindStatsReport(
        total=stats.total,
        verified=stats.verified,
        by_source=[
            LabKindStatsBucket(
                source=b.source, lab_kind=b.lab_kind,
                count=b.count, verified_count=b.verified_count,
            )
            for b in stats.by_source
        ],
        by_kind=[
            LabKindStatsBucket(
                source=b.source, lab_kind=b.lab_kind,
                count=b.count, verified_count=b.verified_count,
            )
            for b in stats.by_kind
        ],
    )


@router.post(
    "/synthesize/gc",
    response_model=SynthesizeGcResponse,
    response_model_by_alias=True,
)
async def synthesize_gc(
    body: SynthesizeGcRequest | None = None,
    db: AsyncSession = Depends(get_db),
) -> SynthesizeGcResponse:
    """Manually trigger LRU eviction of synthesized lab images.

    The same sweep runs opportunistically at every ``synthesize()`` call;
    this endpoint exists for operators who want to force a cleanup (e.g.
    free disk before a big build) or tighten the ceilings ad-hoc by
    passing override targets in the body.
    """
    overrides = body or SynthesizeGcRequest()
    stats = await gc_synthesized_images(
        db,
        target_total_mb=overrides.target_total_mb,
        target_max_count=overrides.target_max_count,
        target_max_age_days=overrides.target_max_age_days,
    )
    return SynthesizeGcResponse(
        scanned=stats.scanned,
        evicted=[
            EvictedImageOut(
                cve_id=e.cve_id,
                image_tag=e.image_tag,
                size_mb=e.size_mb,
                reason=e.reason,
            )
            for e in stats.evicted
        ],
        freed_mb=stats.freed_mb,
        retained_count=stats.retained_count,
        retained_total_mb=stats.retained_total_mb,
        skipped_in_use=stats.skipped_in_use,
    )


@router.post(
    "/sessions",
    response_model=SandboxSessionOut,
    response_model_by_alias=True,
    status_code=status.HTTP_201_CREATED,
)
async def start_session(
    body: SandboxStartRequest,
    db: AsyncSession = Depends(get_db),
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
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

    # PR 9-U manual pivot: when the caller pins a specific synthesized
    # mapping_id, build the ResolvedLab directly off that row so the
    # resolver's score-pick is bypassed. The pinned row must belong to
    # this CVE; on mismatch we silently fall back to the normal chain
    # (the UI never sends a stale id, but a refresh-race could).
    resolved: ResolvedLab | None = None
    if body.mapping_id is not None:
        pinned = await db.get(CveLabMapping, body.mapping_id)
        if (
            pinned is not None
            and pinned.cve_id == vuln.cve_id
            and pinned.kind == LabSourceKind.SYNTHESIZED
            and pinned.verified
        ):
            spec = _spec_from_mapping(pinned)
            resolved = ResolvedLab(
                spec=spec,
                source=LabSourceKind.SYNTHESIZED,
                verified=True,
                mapping_id=pinned.id,
                cached_payload=pinned.known_good_payload,
            )
            log.info(
                "sandbox.start.manual_pivot",
                cve_id=vuln.cve_id,
                mapping_id=pinned.id,
                lab_kind=pinned.lab_kind,
            )

    if resolved is None:
        forced = (body.lab_kind or "").strip().lower() or None
        resolved = await resolve_lab(
            db,
            vuln,
            forced_kind=forced,
            attempt_synthesis=body.attempt_synthesis,
        )
    if resolved is None:
        # If the caller already consented to synthesis and we still can't
        # produce a lab, surface the synthesis failure verbatim. Otherwise
        # invite the caller to opt in via attemptSynthesis=true.
        if body.attempt_synthesis:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "synthesis_failed",
                    "message": (
                        "AI 합성으로도 이 CVE 의 lab 을 만들지 못했습니다. "
                        "/sandbox/synthesize 로 직접 호출하면 빌드 로그와 응답 본문을 "
                        "확인할 수 있습니다."
                    ),
                },
            )
        # Distinguish "never had a lab" from "lab was deliberately demoted
        # by user feedback" — the second deserves an explanation, not the
        # generic onboarding text.
        existing_synth = await db.scalar(
            select(CveLabMapping).where(
                CveLabMapping.cve_id == body.cve_id,
                CveLabMapping.kind == LabSourceKind.SYNTHESIZED,
                CveLabMapping.verified.is_(True),
            )
        )
        if existing_synth is not None and is_degraded(existing_synth):
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "lab_degraded",
                    "canSynthesize": True,
                    "feedbackUp": int(existing_synth.feedback_up or 0),
                    "feedbackDown": int(existing_synth.feedback_down or 0),
                    "message": (
                        "이 CVE 의 합성된 lab 이 사용자 평가로 격하되었습니다 "
                        f"(👍 {existing_synth.feedback_up} / 👎 {existing_synth.feedback_down}). "
                        "재합성을 원하면 attemptSynthesis=true 로 호출하세요. "
                        "(24시간 cooldown 내라면 forceRegenerate=true 로 즉시 재시도)"
                    ),
                },
            )
        raise HTTPException(
            status_code=422,
            detail={
                "code": "no_lab",
                "canSynthesize": True,
                "message": (
                    "이 CVE 에 대응하는 등록된 lab 이 없습니다. "
                    "AI 합성으로 시도하려면 attemptSynthesis=true 로 다시 호출하세요. "
                    "(LLM 토큰 + 수십초~수분 빌드 시간 소요)"
                ),
            },
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

    # Touch last_used_at on the source mapping (if any) so the synthesizer
    # GC keeps hot images around. Generic labs without a cached row have
    # no mapping_id yet — nothing to stamp; the cache row will get one on
    # first successful exec via record_success_payload.
    if resolved.mapping_id is not None:
        mapping = await db.get(CveLabMapping, resolved.mapping_id)
        if mapping is not None:
            mapping.last_used_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(session_row)
    return await _session_to_out(
        db,
        session_row,
        spec=resolved.spec,
        mapping_id=resolved.mapping_id,
        client_id=x_client_id,
    )


@router.get(
    "/sessions/{session_id}",
    response_model=SandboxSessionOut,
    response_model_by_alias=True,
)
async def get_session(
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
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
    return await _session_to_out(db, row, client_id=x_client_id)


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
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
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
        session=await _session_to_out(
            db,
            row,
            spec=resolved.spec,
            mapping_id=resolved.mapping_id,
            client_id=x_client_id,
        ),
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


_VOTE_VALUES = {"up", "down"}


@router.post(
    "/sessions/{session_id}/feedback",
    response_model=LabFeedbackResponse,
    response_model_by_alias=True,
)
async def submit_feedback(
    session_id: UUID,
    body: LabFeedbackRequest,
    db: AsyncSession = Depends(get_db),
    x_client_id: str | None = Header(default=None, alias="X-Client-Id"),
) -> LabFeedbackResponse:
    """Vote on the synthesized lab tied to *session_id*.

    Identity is the anonymous ``X-Client-Id`` header (same convention as
    bookmarks/tickets/community). Re-voting upserts the same row in
    ``cve_lab_feedback`` and recomputes the denormalized counters on the
    mapping. Votes against vulhub / generic labs are refused — those
    aren't subject to the trust gating, so a vote would be misleading.
    """
    if body.vote not in _VOTE_VALUES:
        raise HTTPException(
            status_code=422,
            detail=f"vote must be one of {sorted(_VOTE_VALUES)}",
        )
    if not x_client_id or len(x_client_id) > 64:
        raise HTTPException(
            status_code=400, detail="X-Client-Id header is required"
        )

    row = await db.scalar(
        select(SandboxSession).where(SandboxSession.id == session_id)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    if row.lab_source != LabSourceKind.SYNTHESIZED:
        raise HTTPException(
            status_code=409,
            detail="vulhub / generic lab 은 평가 대상이 아닙니다 — 합성 lab 만 평가 가능합니다.",
        )
    if row.vulnerability_id is None:
        raise HTTPException(
            status_code=409, detail="이 세션에 연결된 CVE 정보를 찾을 수 없습니다."
        )

    # The session's lab_kind embeds the CVE + spec hash; resolve back to
    # the underlying mapping. We don't trust row.lab_kind alone because
    # the mapping might have been re-synthesized since this session
    # started — current mapping is what counts for the trust gate.
    vuln = await db.scalar(
        select(Vulnerability).where(Vulnerability.id == row.vulnerability_id)
    )
    mapping = (
        await db.scalar(
            select(CveLabMapping).where(
                CveLabMapping.cve_id == vuln.cve_id,
                CveLabMapping.kind == LabSourceKind.SYNTHESIZED,
            )
        )
        if vuln is not None
        else None
    )
    if mapping is None:
        raise HTTPException(
            status_code=404, detail="평가할 합성 mapping 이 없습니다."
        )

    fb = await db.scalar(
        select(CveLabFeedback).where(
            CveLabFeedback.mapping_id == mapping.id,
            CveLabFeedback.client_id == x_client_id,
        )
    )
    if fb is None:
        fb = CveLabFeedback(
            mapping_id=mapping.id,
            client_id=x_client_id,
            vote=body.vote,
            note=body.note,
        )
        db.add(fb)
    else:
        fb.vote = body.vote
        fb.note = body.note

    # Recompute denormalized counters from the source of truth (the
    # feedback rows). This costs one extra SELECT but keeps drift
    # impossible — important because the resolver reads these counters
    # to decide ``is_degraded``.
    await db.flush()
    counts = await db.execute(
        select(CveLabFeedback.vote, func.count())
        .where(CveLabFeedback.mapping_id == mapping.id)
        .group_by(CveLabFeedback.vote)
    )
    up = down = 0
    for vote, n in counts.all():
        if vote == "up":
            up = int(n)
        elif vote == "down":
            down = int(n)
    mapping.feedback_up = up
    mapping.feedback_down = down
    await db.commit()

    return LabFeedbackResponse(
        mapping_id=mapping.id,
        feedback_up=up,
        feedback_down=down,
        my_vote=body.vote,
        degraded=is_degraded(mapping),
    )
