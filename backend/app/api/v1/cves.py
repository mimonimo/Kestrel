from fastapi import APIRouter, Body, Depends, HTTPException, Query
from datetime import datetime
from sqlalchemy import or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_user
from app.core.database import get_db
from app.models import (
    AffectedProduct,
    AnalysisResult,
    Severity,
    User,
    Vulnerability,
    vulnerability_type_map,
)
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
    # 원본 소스(raw_data)에서 약점·레퍼런스·CVSS 메트릭 보강 (best-effort).
    from app.services.enrichment import build_enrichment

    vuln.enrichment = build_enrichment(vuln)  # type: ignore[attr-defined]
    return vuln


class RelatedItem(CamelModel):
    cve_id: str
    title: str
    severity: Severity | None = None
    cvss_score: float | None = None
    published_at: datetime | None = None
    kev_listed: bool = False
    reason: str
    # 구조화된 관계 유형(프론트 색상 분류용). product/vendor/weakness_high/
    # weakness_low/weakness/related.
    relation: str = "related"


def _prod_label(vendor: str | None, product: str | None) -> str:
    """벤더+제품을 사람이 읽기 좋게 — 제품명이 이미 벤더로 시작하면 중복 제거
    ("Red Hat" + "Red Hat Enterprise Linux 10" → "Red Hat Enterprise Linux 10")."""
    v = (vendor or "").strip()
    p = (product or "").strip()
    if v and p:
        return p if p.lower().startswith(v.lower()) else f"{v} {p}"
    return p or v


@router.get(
    "/{cve_id}/related",
    response_model=list[RelatedItem],
    response_model_by_alias=True,
)
async def related_cves(cve_id: str, db: AsyncSession = Depends(get_db)) -> list[RelatedItem]:
    """같은 제품 또는 같은 약점(CWE 유형)을 공유하는 다른 CVE 추천 — 분석 맥락용."""
    vuln = await db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
    if vuln is None:
        return []
    prod_pairs = list({(p.vendor, p.product) for p in vuln.affected_products})
    type_ids = [t.id for t in vuln.types]
    self_prods = set(prod_pairs)
    self_vendors = {p.vendor for p in vuln.affected_products if p.vendor}
    self_types = {t.name for t in vuln.types}
    self_score = float(vuln.cvss_score) if vuln.cvss_score is not None else None

    conds = []
    if prod_pairs:
        conds.append(
            Vulnerability.id.in_(
                select(AffectedProduct.vulnerability_id).where(
                    tuple_(AffectedProduct.vendor, AffectedProduct.product).in_(prod_pairs)
                )
            )
        )
    if type_ids:
        conds.append(
            Vulnerability.id.in_(
                select(vulnerability_type_map.c.vulnerability_id).where(
                    vulnerability_type_map.c.type_id.in_(type_ids)
                )
            )
        )
    if not conds:
        return []

    # 후보를 넉넉히(최신순) 모은 뒤 Python 에서 다중 신호로 가중 랭킹한다.
    # 단순 "같은 유형(예: Auth)" 폴백은 너무 느슨해 — 제품 > 같은 벤더 >
    # 유형 겹침 수 > KEV > CVSS 근접 > 최신 순으로 점수화해 상위 8건만 노출.
    stmt = (
        select(Vulnerability)
        .where(Vulnerability.id != vuln.id, or_(*conds))
        .order_by(Vulnerability.published_at.desc().nulls_last())
        .limit(120)
    )
    rows = (await db.execute(stmt)).scalars().unique().all()

    scored: list[tuple[float, float, RelatedItem]] = []
    for r in rows:
        shared_prod = next(
            (p for p in r.affected_products if (p.vendor, p.product) in self_prods), None
        )
        cand_vendors = {p.vendor for p in r.affected_products if p.vendor}
        shared_vendor = next((v for v in cand_vendors if v in self_vendors), None)
        shared_types = [t.name for t in r.types if t.name in self_types]

        score = 0.0
        if shared_prod:
            score += 100
        if shared_vendor:
            score += 35
        score += 12 * len(shared_types)
        if r.kev_listed:
            score += 15
        if self_score is not None and r.cvss_score is not None:
            score += max(0.0, 10 - abs(self_score - float(r.cvss_score)) * 2)

        # 사람이 읽을 근거 — 가장 강한 신호를 앞세우고 부가 신호(공격 유형·심각도
        # 근접)를 덧붙여 "왜 연관인지" 구체적으로. 제품·벤더가 잡히면 공격 유형을
        # 함께, 유형만 잡히는 약한 매치는 심각도 근접 여부까지 밝혀 정당화한다.
        cvss_close = (
            self_score is not None
            and r.cvss_score is not None
            and abs(self_score - float(r.cvss_score)) <= 1.0
        )
        if shared_prod:
            relation = "product"
            reason = f"같은 제품 · {_prod_label(shared_prod.vendor, shared_prod.product)}"
            if shared_types:
                reason += f" · {shared_types[0]} 유형"
        elif shared_vendor:
            relation = "vendor"
            reason = f"같은 벤더 · {shared_vendor}"
            if shared_types:
                reason += f" · {shared_types[0]} 유형"
        elif shared_types:
            reason = f"같은 유형 · {shared_types[0]}"
            if len(shared_types) >= 2:
                reason += f" 외 {len(shared_types) - 1}"
            if cvss_close:
                reason += " · 심각도 비슷"
            # 공통 약점 매치는 현재 CVE 대비 심각도로 상위/하위를 나눠 분석 용이.
            if self_score is not None and r.cvss_score is not None:
                diff = float(r.cvss_score) - self_score
                relation = (
                    "weakness_high" if diff >= 0.5
                    else "weakness_low" if diff <= -0.5
                    else "weakness"
                )
                if diff >= 0.5:
                    reason += " · 상위(더 위험)"
                elif diff <= -0.5:
                    reason += " · 하위"
            else:
                relation = "weakness"
        else:
            relation = "related"
            reason = "연관"

        item = RelatedItem(
            cve_id=r.cve_id,
            title=r.title,
            severity=r.severity,
            cvss_score=float(r.cvss_score) if r.cvss_score is not None else None,
            published_at=r.published_at,
            kev_listed=bool(r.kev_listed),
            reason=reason,
            relation=relation,
        )
        recency = r.published_at.timestamp() if r.published_at else 0.0
        scored.append((score, recency, item))

    scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return [item for _, _, item in scored[:8]]


class ReferencePreviewOut(CamelModel):
    url: str
    title: str | None = None
    description: str | None = None
    site_name: str | None = None
    image: str | None = None
    ok: bool = False


@router.get(
    "/{cve_id}/reference-previews",
    response_model=list[ReferencePreviewOut],
    response_model_by_alias=True,
)
async def reference_previews(cve_id: str, db: AsyncSession = Depends(get_db)) -> list[dict]:
    """이 CVE 참고 링크들의 페이지 제목·요약을 가져온다(서버측, 캐시·SSRF 안전).
    사이트로 나가지 않고도 각 레퍼런스 내용을 미리 보기 위함."""
    vuln = await db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
    if vuln is None:
        return []
    urls: list[str] = []
    raw = vuln.raw_data if isinstance(vuln.raw_data, dict) else {}
    cve = raw.get("cve") if isinstance(raw, dict) else None
    if isinstance(cve, dict):
        for r in cve.get("references") or []:
            if isinstance(r, dict) and r.get("url"):
                urls.append(r["url"])
    if not urls:  # GitHub Advisory 등 평탄 구조 + 모델 references 폴백
        for r in raw.get("references") or []:
            if isinstance(r, dict) and r.get("url"):
                urls.append(r["url"])
    if not urls:
        urls = [r.url for r in vuln.references]
    if not urls:
        return []
    from app.services.reference_preview import previews_for

    return await previews_for(urls)


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
    # 재분석 누적 — 이 사용자가 이 CVE 에 대해 이미 만든 최근 분석을 모아
    # 프롬프트에 함께 넘겨, 같은 내용을 반복하지 말고 더 고도화된 하나의
    # 분석으로 발전시키도록 한다.
    prior_rows = (
        await db.scalars(
            select(AnalysisResult)
            .where(AnalysisResult.cve_id == cve_id, AnalysisResult.user_id == user.id)
            .order_by(AnalysisResult.created_at.desc())
            .limit(2)
        )
    ).all()
    prior_md = "\n\n---\n\n".join(r.result_md for r in prior_rows if r.result_md) or None
    result = await analyze_vulnerability(db, vuln, user_id=user.id, prior_md=prior_md)

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
