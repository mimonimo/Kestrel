"""Deep-analysis endpoints — follow-up Q&A on an existing CVE analysis,
and pattern comparison across 2-5 CVEs.

The base ``/cves/{cve_id}/analyze`` produces the structured first-pass
analysis. Operators then need two things on top of that:

1. *Follow-up* — drilling into a specific payload variant or asking
   "what about defense-in-depth at layer X?" without re-running the
   whole structured analysis.
2. *Comparison* — looking at a cluster of recent CVEs and asking
   "what's the common thread? can one control cover all of them?".

Both reuse the active AI credential (whatever the user has selected in
settings) — no separate config.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import Vulnerability
from app.schemas.vulnerability import CamelModel
from app.services.ai_analyzer import (
    AiAnalysis,
    answer_followup_question,
    compare_vulnerabilities,
)

router = APIRouter(prefix="/analysis", tags=["analysis"])


# ─────────────────────── Follow-up Q&A ───────────────────────────────


class PriorAnalysisPayload(CamelModel):
    """Subset of the structured analysis that the model needs to recall."""

    attack_method: str
    payload_examples: list[str]
    mitigations: list[str]


class QaTurn(CamelModel):
    question: str
    answer: str


class AskRequest(CamelModel):
    cve_id: str
    question: Annotated[str, Field(min_length=1, max_length=2000)]
    prior: PriorAnalysisPayload | None = None
    history: list[QaTurn] = Field(default_factory=list)


class AskResponse(CamelModel):
    answer: str


@router.post(
    "/ask",
    response_model=AskResponse,
    response_model_by_alias=True,
)
async def ask_followup(
    body: Annotated[AskRequest, Body()],
    db: AsyncSession = Depends(get_db),
) -> AskResponse:
    vuln = await db.scalar(
        select(Vulnerability).where(Vulnerability.cve_id == body.cve_id)
    )
    if vuln is None:
        raise HTTPException(status_code=404, detail=f"{body.cve_id} not found")

    prior_obj: AiAnalysis | None = None
    if body.prior is not None:
        prior_obj = AiAnalysis(
            attack_method=body.prior.attack_method,
            payload_examples=list(body.prior.payload_examples),
            mitigations=list(body.prior.mitigations),
        )

    history_pairs = [(t.question, t.answer) for t in body.history]
    answer = await answer_followup_question(
        db,
        vuln,
        prior_obj,
        history_pairs,
        body.question,
    )
    return AskResponse(answer=answer)


# ─────────────────────── CVE comparison ──────────────────────────────


class CompareRequest(CamelModel):
    cve_ids: Annotated[list[str], Field(min_length=2, max_length=5)]


class PerCveNote(CamelModel):
    cve_id: str
    note: str


class CompareResponse(CamelModel):
    summary: str
    common_pattern: str
    differences: list[str]
    shared_mitigations: list[str]
    per_cve_notes: list[PerCveNote]


@router.post(
    "/compare",
    response_model=CompareResponse,
    response_model_by_alias=True,
)
async def compare(
    body: Annotated[CompareRequest, Body()],
    db: AsyncSession = Depends(get_db),
) -> CompareResponse:
    # Dedupe while preserving order so the LLM sees the same sequence
    # the user clicked in the UI.
    seen: set[str] = set()
    ordered: list[str] = []
    for cid in body.cve_ids:
        if cid not in seen:
            seen.add(cid)
            ordered.append(cid)

    rows = (
        await db.execute(
            select(Vulnerability).where(Vulnerability.cve_id.in_(ordered))
        )
    ).scalars().all()
    by_id = {v.cve_id: v for v in rows}
    missing = [c for c in ordered if c not in by_id]
    if missing:
        raise HTTPException(
            status_code=404,
            detail=f"CVE not found: {', '.join(missing)}",
        )

    vulns = [by_id[c] for c in ordered]
    result = await compare_vulnerabilities(db, vulns)
    return CompareResponse(
        summary=result.summary,
        common_pattern=result.common_pattern,
        differences=result.differences,
        shared_mitigations=result.shared_mitigations,
        per_cve_notes=[PerCveNote(**n) for n in result.per_cve_notes],
    )
