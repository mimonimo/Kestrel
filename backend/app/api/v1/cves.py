from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Query
from datetime import datetime
from sqlalchemy import func, select, text, tuple_
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
from app.services.notifications import notify_author_subscribers

router = APIRouter(prefix="/cves", tags=["cves"])

# 연관 CVE 후보 id 집합 상한(브랜치별). 흔한 벤더/제품 pair 가 수만 건을
# 매칭해도 후보를 이 수로 제한해 2단계 조회의 IN 리스트·정렬 비용을 유계로
# 만든다. 최종적으로 상위 8건만 노출하므로 랭킹 품질에 실질 영향 없음.
_RELATED_CANDIDATE_CAP = 3000

# 일부 CVE 는 영향 제품 (vendor,product) pair 를 수천 개 나열한다(데이터 품질
# 이슈; 예: 5,400개). `tuple_(...).in_(pairs)` 의 IN 절이 그만큼 커져 무거워지고
# 복합 인덱스도 pair 당 개별 프로브로 되레 악화된다. pair 를 이 수로 제한해
# IN 절을 유계로 유지 — 연관 추천은 상위 8건만 노출하므로 실질 영향 없음.
_RELATED_PAIR_CAP = 300


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


_SITEMAP_MAX = 10_000  # 사이트맵에 노출할 최근 CVE 상한 — 쿼리/응답 크기 상한(과부하 방지).


class SitemapId(CamelModel):
    cve_id: str
    modified_at: datetime | None = None
    published_at: datetime | None = None


@router.get("/sitemap-ids", response_model=list[SitemapId], response_model_by_alias=True)
async def sitemap_ids(
    limit: int = Query(5000, ge=1, le=_SITEMAP_MAX),
    offset: int = Query(0, ge=0, le=_SITEMAP_MAX),
    db: AsyncSession = Depends(get_db),
) -> list[SitemapId]:
    """공개 CVE 상세 페이지용 경량 ID 목록 — 검색/AI 크롤러 발견성용 사이트맵 생성에서만 사용.

    보안/과부하 검토:
    - 공개 데이터(이미 누구나 GET /cves/{id} 로 열람)만, 가벼운 컬럼(cve_id·날짜)만 반환.
    - 인증·관리·에이전트 토큰 등 어떤 비공개 정보도 노출하지 않음.
    - offset+limit 를 _SITEMAP_MAX(1만)로 강제 상한 → 깊은 페이징/대량 스캔으로 인한
      부하·DoS 방지. published_at 인덱스(ix_vuln_published_desc)로 정렬해 비용 한정.
    """
    capped = min(limit, max(0, _SITEMAP_MAX - offset))
    if capped <= 0:
        return []
    rows = (
        await db.execute(
            select(
                Vulnerability.cve_id,
                Vulnerability.modified_at,
                Vulnerability.published_at,
            )
            .order_by(Vulnerability.published_at.desc().nulls_last())
            .limit(capped)
            .offset(offset)
        )
    ).all()
    return [
        SitemapId(cve_id=cid, modified_at=mod, published_at=pub)
        for cid, mod, pub in rows
    ]


@router.get("/{cve_id}", response_model=VulnerabilityDetail, response_model_by_alias=True)
async def get_cve(cve_id: str, db: AsyncSession = Depends(get_db)) -> Vulnerability:
    vuln = await db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
    if vuln is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found")
    # 원본 소스(raw_data)에서 약점·레퍼런스·CVSS 메트릭 보강 (best-effort).
    from app.services.enrichment import build_enrichment

    vuln.enrichment = build_enrichment(vuln)  # type: ignore[attr-defined]

    # CISA SSVC 기반 권장 대응 기한(KEV·EPSS·CVSS 신호로 도출).
    from app.services.ssvc import remediation_for

    vuln.remediation = remediation_for(vuln)  # type: ignore[attr-defined]
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
    # self_prods 는 스코어링용(전체 제품), query_pairs 는 IN 절 크기를 유계로
    # 만들기 위해 상한을 씌운 부분집합 — 캡을 넘는 제품도 벤더 매칭으로는 여전히
    # 후보에 잡히므로 연관 품질 손실은 미미하다.
    self_prods = {(p.vendor, p.product) for p in vuln.affected_products}
    query_pairs = list(self_prods)[:_RELATED_PAIR_CAP]
    type_ids = [t.id for t in vuln.types]
    self_vendors = {p.vendor for p in vuln.affected_products if p.vendor}
    self_types = {t.name for t in vuln.types}
    self_score = float(vuln.cvss_score) if vuln.cvss_score is not None else None

    # 후보 vuln-id 집합을 먼저 구한 뒤(정렬·LIMIT 없이) 그 작은 집합만 최신순
    # 정렬한다. 예전엔 `id IN (semi-join) ORDER BY published_at LIMIT 120` 이
    # 플래너에서 "published_at 인덱스를 최신순으로 훑으며 매 행 affected_products
    # 프로브" 계획으로 풀려, cisco 처럼 흔한 벤더에선 7만+ 행을 스캔해 20초
    # statement timeout 을 넘겼다(→ QueryCanceledError → AppErrors 알람). 후보
    # 집합을 먼저 만들면(예: cisco ≈ 1,254건) 정렬 대상이 작아 <1s 로 떨어진다.
    # 병적으로 흔한 pair(수만 건 매칭)는 CAP 으로 상한 — 어차피 상위 8건만 노출.
    cand_ids: set = set()
    if query_pairs:
        cand_ids.update(
            (
                await db.execute(
                    select(AffectedProduct.vulnerability_id)
                    .where(tuple_(AffectedProduct.vendor, AffectedProduct.product).in_(query_pairs))
                    .distinct()
                    .limit(_RELATED_CANDIDATE_CAP)
                )
            ).scalars().all()
        )
    if type_ids:
        cand_ids.update(
            (
                await db.execute(
                    select(vulnerability_type_map.c.vulnerability_id)
                    .where(vulnerability_type_map.c.type_id.in_(type_ids))
                    .distinct()
                    .limit(_RELATED_CANDIDATE_CAP)
                )
            ).scalars().all()
        )
    cand_ids.discard(vuln.id)
    if not cand_ids:
        return []

    # 후보만 최신순으로 정렬해 상위 120건 → Python 에서 다중 신호로 가중 랭킹.
    # (제품 > 같은 벤더 > 유형 겹침 수 > KEV > CVSS 근접 > 최신 순, 상위 8건 노출.)
    #
    # `id IN (...) ORDER BY published_at LIMIT 120` 을 그대로 두면, 후보 집합을
    # 미리 좁혀놨어도 플래너가 여전히 "published_at 인덱스를 최신순으로 역주행하며
    # 매 행 id 필터" 계획을 택한다. cisco(1,254건)·log4shell(5,942건)처럼 후보가
    # 오래된 CVE 면 120건을 채우기까지 37만 행 대부분을 스캔 → 25초, statement
    # timeout(20s)을 넘겨 500(QueryCanceledError)→AppErrors 알람. CTE 를
    # MATERIALIZED 로 강제하면 후보 집합(≤6000)을 PK 로 먼저 구체화한 뒤 그 작은
    # 집합만 정렬 → 실측 23~73ms. id = ANY(array) 로 거대 IN 리스트 전개도 회피.
    top_ids = (
        await db.execute(
            text(
                "WITH c AS MATERIALIZED ("
                "  SELECT id, published_at FROM vulnerabilities WHERE id = ANY(:ids)"
                ") SELECT id FROM c ORDER BY published_at DESC NULLS LAST LIMIT 120"
            ),
            {"ids": list(cand_ids)},
        )
    ).scalars().all()
    if not top_ids:
        return []
    # 상위 120건만 ORM 로 적재(관계는 selectin) — 정렬은 아래 스코어링이 다시
    # 하므로 여기선 순서 무관, 작은 IN(120) 이라 병리 없음.
    rows = (
        await db.execute(select(Vulnerability).where(Vulnerability.id.in_(top_ids)))
    ).scalars().unique().all()

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
    background_tasks: BackgroundTasks,
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
    # 기본 공개여부 — 사용자 설정(default_analysis_public)을 따른다. 설정 ON 이면
    # 새 분석이 바로 커뮤니티에 공유(public)되고, OFF(기본)면 비공개로 저장 후
    # 분석 피드에서 개별 공유. body.visibility 가 명시되면 그 값이 우선.
    default_vis = "public" if getattr(user, "default_analysis_public", False) else "private"
    visibility = (body.visibility if body else None) or default_vis
    if visibility not in {"public", "private"}:
        visibility = "private"
    # 구독 알림 스팸 방지 — 이 사용자가 이 CVE 에 이미 공개 분석을 낸 적이 있으면
    # 재분석(누적)이므로 구독자에게 다시 알리지 않는다. 첫 공개 분석에만 전달.
    prior_public = await db.scalar(
        select(func.count(AnalysisResult.id)).where(
            AnalysisResult.cve_id == cve_id,
            AnalysisResult.user_id == user.id,
            AnalysisResult.visibility == "public",
        )
    )
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

    # 첫 공개 분석이면 구독자의 알림채널로 전달(응답 후 백그라운드, best-effort).
    if visibility == "public" and not prior_public:
        background_tasks.add_task(
            notify_author_subscribers, user.id, "analysis", record.title, f"/cve/{cve_id}"
        )

    return AiAnalysisResponse(
        attack_method=result.attack_method,
        payload_examples=result.payload_examples,
        mitigations=result.mitigations,
        analysis_id=str(record.id),
    )
