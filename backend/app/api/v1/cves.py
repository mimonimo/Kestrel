from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_user
from app.core.database import get_db
from app.models import AnalysisResult, User, Vulnerability
from app.schemas.vulnerability import CamelModel, VulnerabilityDetail, VulnerabilityListItem
from app.services.ai_analyzer import analyze_vulnerability

router = APIRouter(prefix="/cves", tags=["cves"])


@router.get("", response_model=list[VulnerabilityListItem], response_model_by_alias=True)
async def list_cves(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[Vulnerability]:
    """Recent vulnerabilities, newest first. Falls back to DB when the search
    service isn't the right fit (e.g. no query/filters).
    """
    stmt = (
        select(Vulnerability)
        .order_by(Vulnerability.published_at.desc().nulls_last())
        .limit(limit)
        .offset(offset)
    )
    return (await db.execute(stmt)).scalars().unique().all()


@router.get("/batch", response_model=list[VulnerabilityListItem], response_model_by_alias=True)
async def batch_cves(
    ids: str = Query(..., description="Comma-separated CVE IDs"),
    db: AsyncSession = Depends(get_db),
) -> list[Vulnerability]:
    """Fetch a list of CVEs by ID — used by the client-side bookmarks filter
    so we don't make one round-trip per bookmark."""
    parsed = [s.strip() for s in ids.split(",") if s.strip()][:200]
    if not parsed:
        return []
    rows = (
        (await db.execute(select(Vulnerability).where(Vulnerability.cve_id.in_(parsed))))
        .scalars()
        .unique()
        .all()
    )
    order = {cid: i for i, cid in enumerate(parsed)}
    rows.sort(key=lambda v: order.get(v.cve_id, 9999))
    return rows


@router.get("/{cve_id}", response_model=VulnerabilityDetail, response_model_by_alias=True)
async def get_cve(cve_id: str, db: AsyncSession = Depends(get_db)) -> Vulnerability:
    vuln = await db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
    if vuln is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found")
    return vuln


class AiAnalysisResponse(CamelModel):
    attack_method: str
    payload_examples: list[str]
    mitigations: list[str]
    # 저장된 분석 레코드 id (PR 10-CN). 프런트엔드는 이걸로 디테일/삭제 가능.
    analysis_id: str | None = None


class AnalyzeRequest(CamelModel):
    """선택적 메타 — 카테고리·공개여부. 미지정 시 general/public."""

    category: str | None = None
    title: str | None = None
    visibility: str | None = None  # "public" | "private"


@router.post(
    "/{cve_id}/analyze",
    response_model=AiAnalysisResponse,
    response_model_by_alias=True,
)
async def analyze_cve(
    cve_id: str,
    body: AnalyzeRequest | None = Body(default=None),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AiAnalysisResponse:
    """LLM 으로 CVE 분석을 실행하고 결과를 DB 에 영구 저장 (로그인 필수).

    400 — settings 의 AI 자격증명/모델 미구성.
    401 — 비로그인.
    404 — 존재하지 않는 CVE.
    """
    vuln = await db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
    if vuln is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found")
    result = await analyze_vulnerability(db, vuln, user_id=user.id)

    # 분석 본문을 마크다운으로 직렬화 후 영구 저장.
    md_lines = ["## 공격 방법", "", result.attack_method, "", "## 페이로드 예시", ""]
    for idx, p in enumerate(result.payload_examples, 1):
        md_lines += [f"### 예시 {idx}", "", "```", p, "```", ""]
    md_lines += ["## 완화 방안", ""]
    md_lines += [f"- {m}" for m in result.mitigations]
    # 기본 비공개 — 사용자가 명시적으로 "공유" 액션을 취해야 커뮤니티 피드에 노출.
    # 운영자 의도: 분석은 본인 자료고, 공개는 분석 피드의 별도 모달에서 선택.
    visibility = (body.visibility if body else None) or "private"
    if visibility not in {"public", "private"}:
        visibility = "private"
    record = AnalysisResult(
        cve_id=cve_id,
        user_id=user.id,
        category=(body.category if body else None) or "general",
        title=(body.title if body else None) or f"{cve_id} — 기본 분석",
        prompt_md=None,
        result_md="\n".join(md_lines),
        visibility=visibility,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)

    return AiAnalysisResponse(
        attack_method=result.attack_method,
        payload_examples=result.payload_examples,
        mitigations=result.mitigations,
        analysis_id=str(record.id),
    )
