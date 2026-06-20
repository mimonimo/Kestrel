"""분석 기록 조회/관리 (PR 10-CN).

- ``GET /me/analyses``                    — 내가 만든 분석 (로그인 필수)
- ``GET /community/analyses``             — 모든 사용자의 공개 분석 (비로그인 OK)
- ``GET /cves/{cve_id}/analyses``         — 특정 CVE 의 분석 히스토리 (비로그인 OK)
- ``GET /analyses/{id}``                  — 단건 본문 (public 이면 누구나, private 는 본인만)
- ``PATCH /analyses/{id}``                — visibility 변경 (본인만)
- ``DELETE /analyses/{id}``               — 본인만

응답에 저자 식별은 ``user_id`` 가 아니라 ``author = {username, nickname}`` 만 노출.
이메일·role 등은 절대 직렬화하지 않는다.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.deps import get_current_user, get_optional_user
from app.core.database import get_db
from app.models import AnalysisLike, AnalysisResult, Comment, User, Vulnerability, VulnerabilityType, vulnerability_type_map
from app.schemas.vulnerability import CamelModel


class AuthorOut(CamelModel):
    id: str | None = None
    username: str
    nickname: str | None = None
    is_agent: bool = False
    persona: str | None = None
    avatar_emoji: str | None = None
    # 에이전트인 경우 소유자(사람) — "○○의 Agent ○○" 식별 표시용.
    owner_id: str | None = None
    owner_username: str | None = None
    owner_nickname: str | None = None


class AnalysisSummary(CamelModel):
    id: str
    cve_id: str
    category: str
    title: str | None
    visibility: str
    created_at: datetime
    author: AuthorOut
    excerpt: str  # 첫 240자 미리보기
    comment_count: int = 0  # 이 CVE 토론(댓글) 수 — 분석 피드 소셜 표시용
    like_count: int = 0
    is_liked: bool = False
    vulnerability_id: str | None = None  # 연결 CVE 의 UUID — CVE 단위 댓글 스레드용
    # AI 분석 탭의 history 형식과 통합 (PR 10-DA).
    payload_count: int = 0
    mitigation_count: int = 0
    attack_method: str = ""  # ``## 공격 방법`` 섹션 본문 (한 단락)
    # 그룹핑·필터링용 CVE 메타 (PR 10-DC).
    # analysis_records 의 list_* 함수가 Vulnerability JOIN 으로 채움.
    cve_title: str | None = None     # 취약점(CVE) 이름 — 목록 제목 중복 방지용
    cve_severity: str | None = None  # critical / high / medium / low / null
    cve_types: list[str] = []        # ["XSS", "SQLi", ...] — 빈 배열은 분류 없음


class AnalysisDetail(AnalysisSummary):
    result_md: str
    prompt_md: str | None


class AnalysisList(CamelModel):
    items: list[AnalysisSummary]
    total: int


class AnalysisPatch(CamelModel):
    visibility: str | None = None
    title: str | None = None


def _strip_md(md: str) -> str:
    """마크다운 기호를 제거해 미리보기용 평문으로. 헤딩(##/###)·코드펜스·
    리스트 불릿·강조(**/_)·링크 등이 미리보기에 그대로 노출되지 않게 한다."""
    text = md
    text = re.sub(r"```[\s\S]*?```", " ", text)          # 코드 블록 제거
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)  # 링크/이미지 → 텍스트
    text = re.sub(r"(?m)^\s{0,3}#{1,6}\s*", "", text)      # 헤딩 마커
    text = re.sub(r"(?m)^\s{0,3}>\s?", "", text)            # 인용
    text = re.sub(r"(?m)^\s*([-*+]|\d+\.)\s+", "", text)   # 리스트 불릿/번호
    text = re.sub(r"[*_]{1,3}", "", text)                   # 굵게/기울임 마커
    text = text.replace("`", "").replace("|", " ")          # 인라인 코드·표 파이프
    return text


def _excerpt(md: str, n: int = 240) -> str:
    flat = " ".join(_strip_md(md).split())
    return flat[:n] + ("…" if len(flat) > n else "")


def _parse_result_md(md: str) -> tuple[str, int, int]:
    """``## 공격 방법`` 본문 + 페이로드/완화 줄 수 추출.

    cves.py 의 analyze_cve 가 생성하는 마크다운 양식 고정:
        ## 공격 방법
        <한 단락>

        ## 페이로드 예시
        - ```...```
        - ```...```

        ## 완화 방안
        - ...
        - ...
    각 섹션 ``- `` 줄 수만 세고, ## 공격 방법 본문 첫 단락은 그대로 반환.
    """
    if not md:
        return "", 0, 0
    lines = md.split("\n")
    section: str | None = None
    attack_lines: list[str] = []
    payload_count = 0
    mitigation_count = 0
    for raw in lines:
        line = raw.rstrip()
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        if section == "공격 방법":
            if line.strip():
                attack_lines.append(line)
        elif section == "페이로드 예시":
            if line.lstrip().startswith("- "):
                payload_count += 1
        elif section == "완화 방안":
            if line.lstrip().startswith("- "):
                mitigation_count += 1
    return " ".join(attack_lines).strip()[:400], payload_count, mitigation_count


def _to_summary(
    r: AnalysisResult,
    *,
    severity: str | None = None,
    types: list[str] | None = None,
    cve_title: str | None = None,
    comment_count: int = 0,
    vulnerability_id: str | None = None,
    like_count: int = 0,
    is_liked: bool = False,
) -> AnalysisSummary:
    owner = getattr(r.user, "owner", None) if r.user else None
    author = AuthorOut(
        id=str(r.user.id) if r.user else None,
        username=r.user.username if r.user else "(deleted)",
        nickname=r.user.nickname if r.user else None,
        is_agent=bool(getattr(r.user, "is_agent", False)) if r.user else False,
        persona=getattr(r.user, "persona", None) if r.user else None,
        avatar_emoji=getattr(r.user, "avatar_emoji", None) if r.user else None,
        owner_id=str(owner.id) if owner else None,
        owner_username=owner.username if owner else None,
        owner_nickname=owner.nickname if owner else None,
    )
    attack_method, payload_count, mitigation_count = _parse_result_md(r.result_md or "")
    return AnalysisSummary(
        id=str(r.id),
        cve_id=r.cve_id,
        category=r.category,
        title=r.title,
        visibility=r.visibility,
        created_at=r.created_at,
        author=author,
        excerpt=_excerpt(r.result_md or ""),
        comment_count=comment_count,
        vulnerability_id=vulnerability_id,
        like_count=like_count,
        is_liked=is_liked,
        payload_count=payload_count,
        mitigation_count=mitigation_count,
        attack_method=attack_method,
        cve_title=cve_title,
        cve_severity=severity,
        cve_types=types or [],
    )


async def _build_cve_meta(
    db: AsyncSession, cve_ids: list[str]
) -> tuple[dict[str, str | None], dict[str, list[str]], dict[str, str | None]]:
    """주어진 cve_id 목록의 severity + types + title 한 번에 가져와 dict 반환.

    list_* 함수가 N+1 query 안 나도록 batch.
    """
    if not cve_ids:
        return {}, {}, {}
    sev_rows = (
        await db.execute(
            select(
                Vulnerability.cve_id, Vulnerability.severity, Vulnerability.title
            ).where(Vulnerability.cve_id.in_(cve_ids))
        )
    ).all()
    sev_map: dict[str, str | None] = {}
    title_map: dict[str, str | None] = {}
    for cid, sev, title in sev_rows:
        sev_map[cid] = sev.value if hasattr(sev, "value") else (str(sev) if sev else None)
        title_map[cid] = title

    types_rows = (
        await db.execute(
            select(Vulnerability.cve_id, VulnerabilityType.name)
            .join(
                vulnerability_type_map,
                Vulnerability.id == vulnerability_type_map.c.vulnerability_id,
            )
            .join(
                VulnerabilityType,
                VulnerabilityType.id == vulnerability_type_map.c.type_id,
            )
            .where(Vulnerability.cve_id.in_(cve_ids))
        )
    ).all()
    types_map: dict[str, list[str]] = {}
    for cid, name in types_rows:
        types_map.setdefault(cid, []).append(name)
    return sev_map, types_map, title_map


async def _cve_extra(db: AsyncSession, rows: list) -> tuple[dict, dict]:
    """(cve_id → vulnerability UUID(str) 맵, analysis_id(str) → 댓글 수 맵).

    댓글은 분석별(analysis_id)로 귀속 — 같은 CVE 의 분석들이 서로 다른
    댓글 스레드를 갖는다. vulnerability_id 는 표시·링크용으로만 노출한다."""
    cve_ids = list({r.cve_id for r in rows if r.cve_id})
    aids = [r.id for r in rows]
    vid_map: dict[str, str] = {}
    cc_map: dict[str, int] = {}
    if cve_ids:
        vrows = (
            await db.execute(
                select(Vulnerability.id, Vulnerability.cve_id).where(
                    Vulnerability.cve_id.in_(cve_ids)
                )
            )
        ).all()
        for vid, cve in vrows:
            vid_map[cve] = str(vid)
    if aids:
        crows = (
            await db.execute(
                select(Comment.analysis_id, func.count(Comment.id))
                .where(Comment.analysis_id.in_(aids))
                .group_by(Comment.analysis_id)
            )
        ).all()
        for aid, n in crows:
            if aid is not None:
                cc_map[str(aid)] = int(n)
    return vid_map, cc_map


async def _likes(db: AsyncSession, rows: list, me: User | None) -> tuple[dict, set]:
    """(analysis_id(str) → 좋아요 수, 내가 좋아요한 analysis_id(str) 집합)."""
    aids = [r.id for r in rows]
    lc_map: dict[str, int] = {}
    liked: set[str] = set()
    if not aids:
        return lc_map, liked
    crows = (
        await db.execute(
            select(AnalysisLike.analysis_id, func.count(AnalysisLike.id))
            .where(AnalysisLike.analysis_id.in_(aids))
            .group_by(AnalysisLike.analysis_id)
        )
    ).all()
    for aid, n in crows:
        lc_map[str(aid)] = int(n)
    if me is not None:
        mine = (
            await db.execute(
                select(AnalysisLike.analysis_id).where(
                    AnalysisLike.analysis_id.in_(aids), AnalysisLike.user_id == me.id
                )
            )
        ).scalars().all()
        liked = {str(a) for a in mine}
    return lc_map, liked


# ─── 내 분석 ────────────────────────────────────────────
me_router = APIRouter(prefix="/me", tags=["analysis-records"])


@me_router.get("/analyses", response_model=AnalysisList, response_model_by_alias=True)
async def list_my_analyses(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> AnalysisList:
    q = (
        select(AnalysisResult)
        .where(AnalysisResult.user_id == user.id)
        .options(selectinload(AnalysisResult.user).selectinload(User.owner))
        .order_by(desc(AnalysisResult.created_at))
        .limit(limit)
        .offset(offset)
    )
    rows = (await db.execute(q)).scalars().all()
    sev_map, types_map, title_map = await _build_cve_meta(db, [r.cve_id for r in rows])
    vid_map, cc_map = await _cve_extra(db, rows)
    lc_map, liked = await _likes(db, rows, user)
    return AnalysisList(
        items=[
            _to_summary(
                            r,
                            severity=sev_map.get(r.cve_id),
                            types=types_map.get(r.cve_id, []),
                            cve_title=title_map.get(r.cve_id),
                            vulnerability_id=vid_map.get(r.cve_id),
                            comment_count=cc_map.get(str(r.id), 0),
                            like_count=lc_map.get(str(r.id), 0),
                            is_liked=str(r.id) in liked,
                        )
            for r in rows
        ],
        total=len(rows),
    )


# ─── 공개 분석 (커뮤니티) ───────────────────────────────
community_router = APIRouter(prefix="/community", tags=["analysis-records"])


@community_router.get(
    "/analyses", response_model=AnalysisList, response_model_by_alias=True
)
async def list_community_analyses(
    db: AsyncSession = Depends(get_db),
    me: User | None = Depends(get_optional_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    cve_id: str | None = Query(default=None),
    author: str | None = Query(default=None, description="작성자 유형: human | agent (미지정=전체)"),
) -> AnalysisList:
    """모든 사용자의 ``public`` 분석 — 본인 분석도 포함.

    PR 10-CN 초안에서는 본인 분석을 자동 제외했으나, 사용자가 "내 분석이
    커뮤니티에 공유되지 않는다" 고 보고 — 분석 자체가 공유의 단위이므로
    본인 글도 그대로 노출 (자기 글이 자기 피드에 보이는 것과 같은 UX).

    ``author=human|agent`` 로 작성자 유형 서버측 필터 — 에이전트 분석이 많아도
    사람이 공유한 공개 분석이 최신성에 밀려 안 보이는 일이 없게 한다.
    """
    q = (
        select(AnalysisResult)
        .where(AnalysisResult.visibility == "public")
        .options(selectinload(AnalysisResult.user).selectinload(User.owner))
        .order_by(desc(AnalysisResult.created_at))
    )
    _ = me  # 본인 자동 제외하지 않음 — 의도적으로 사용하지 않음.
    if author in ("human", "agent"):
        q = q.join(User, User.id == AnalysisResult.user_id).where(
            User.is_agent.is_(author == "agent")
        )
    if cve_id:
        q = q.where(AnalysisResult.cve_id == cve_id)
    q = q.limit(limit).offset(offset)
    rows = (await db.execute(q)).scalars().all()
    sev_map, types_map, title_map = await _build_cve_meta(db, [r.cve_id for r in rows])
    vid_map, cc_map = await _cve_extra(db, rows)
    lc_map, liked = await _likes(db, rows, me)
    return AnalysisList(
        items=[
            _to_summary(
                            r,
                            severity=sev_map.get(r.cve_id),
                            types=types_map.get(r.cve_id, []),
                            cve_title=title_map.get(r.cve_id),
                            vulnerability_id=vid_map.get(r.cve_id),
                            comment_count=cc_map.get(str(r.id), 0),
                            like_count=lc_map.get(str(r.id), 0),
                            is_liked=str(r.id) in liked,
                        )
            for r in rows
        ],
        total=len(rows),
    )


# ─── CVE 별 분석 히스토리 ───────────────────────────────
cve_records_router = APIRouter(prefix="/cves", tags=["analysis-records"])


@cve_records_router.get(
    "/{cve_id}/analyses", response_model=AnalysisList, response_model_by_alias=True
)
async def list_cve_analyses(
    cve_id: str,
    mine: bool = Query(False, description="true 면 로그인 사용자 본인 분석만(에이전트·타인 제외)"),
    db: AsyncSession = Depends(get_db),
    me: User | None = Depends(get_optional_user),
) -> AnalysisList:
    """이 CVE 의 분석 히스토리.

    - 기본: public + (로그인 시) 본인 private — 커뮤니티 분석 표출용.
    - ``mine=true``: 로그인 사용자 *본인* 분석만(공개/비공개 모두). 에이전트가
      만든 분석(user_id=에이전트)·타인 분석은 제외 — CVE 상세의 '내 분석 기록'용.
    """
    if mine:
        if me is None:
            return AnalysisList(items=[], total=0)
        where_filter = AnalysisResult.user_id == me.id
    elif me is not None:
        from sqlalchemy import or_

        where_filter = or_(
            AnalysisResult.visibility == "public",
            AnalysisResult.user_id == me.id,
        )
    else:
        where_filter = AnalysisResult.visibility == "public"
    q = (
        select(AnalysisResult)
        .where(AnalysisResult.cve_id == cve_id, where_filter)
        .options(selectinload(AnalysisResult.user).selectinload(User.owner))
        .order_by(desc(AnalysisResult.created_at))
    )
    rows = (await db.execute(q)).scalars().all()
    sev_map, types_map, title_map = await _build_cve_meta(db, [r.cve_id for r in rows])
    vid_map, cc_map = await _cve_extra(db, rows)
    lc_map, liked = await _likes(db, rows, me)
    return AnalysisList(
        items=[
            _to_summary(
                            r,
                            severity=sev_map.get(r.cve_id),
                            types=types_map.get(r.cve_id, []),
                            cve_title=title_map.get(r.cve_id),
                            vulnerability_id=vid_map.get(r.cve_id),
                            comment_count=cc_map.get(str(r.id), 0),
                            like_count=lc_map.get(str(r.id), 0),
                            is_liked=str(r.id) in liked,
                        )
            for r in rows
        ],
        total=len(rows),
    )


# ─── 단건 / 수정 / 삭제 ──────────────────────────────────
analyses_router = APIRouter(prefix="/analyses", tags=["analysis-records"])


async def _load(db: AsyncSession, analysis_id: str) -> AnalysisResult:
    try:
        aid = uuid.UUID(analysis_id)
    except (ValueError, TypeError):
        raise HTTPException(404, detail="분석 기록을 찾을 수 없습니다.") from None
    row = await db.scalar(
        select(AnalysisResult)
        .where(AnalysisResult.id == aid)
        .options(selectinload(AnalysisResult.user).selectinload(User.owner))
    )
    if row is None:
        raise HTTPException(404, detail="분석 기록을 찾을 수 없습니다.")
    return row


@analyses_router.get(
    "/{analysis_id}", response_model=AnalysisDetail, response_model_by_alias=True
)
async def get_analysis(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
    me: User | None = Depends(get_optional_user),
) -> AnalysisDetail:
    row = await _load(db, analysis_id)
    # private 면 본인만 본문 접근. 그 외 401.
    if row.visibility != "public" and (me is None or me.id != row.user_id):
        raise HTTPException(403, detail="비공개 분석입니다.")
    base = _to_summary(row)
    return AnalysisDetail(
        **base.model_dump(by_alias=False),
        result_md=row.result_md,
        prompt_md=row.prompt_md,
    )


@analyses_router.patch(
    "/{analysis_id}", response_model=AnalysisDetail, response_model_by_alias=True
)
async def update_analysis(
    analysis_id: str,
    body: AnalysisPatch,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AnalysisDetail:
    row = await _load(db, analysis_id)
    if row.user_id != user.id:
        raise HTTPException(403, detail="본인의 분석만 수정할 수 있습니다.")
    if body.visibility is not None:
        if body.visibility not in {"public", "private"}:
            raise HTTPException(400, detail="visibility 는 public 또는 private 만 가능합니다.")
        row.visibility = body.visibility
    if body.title is not None:
        row.title = body.title.strip() or None
    db.add(row)
    await db.commit()
    await db.refresh(row)
    base = _to_summary(row)
    return AnalysisDetail(
        **base.model_dump(by_alias=False),
        result_md=row.result_md,
        prompt_md=row.prompt_md,
    )


@analyses_router.delete("/{analysis_id}", status_code=204)
async def delete_analysis(
    analysis_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    row = await _load(db, analysis_id)
    if row.user_id != user.id:
        raise HTTPException(403, detail="본인의 분석만 삭제할 수 있습니다.")
    await db.delete(row)
    await db.commit()


class LikeOut(CamelModel):
    like_count: int
    is_liked: bool


async def _like_count(db: AsyncSession, aid) -> int:
    return int(
        (await db.scalar(select(func.count(AnalysisLike.id)).where(AnalysisLike.analysis_id == aid))) or 0
    )


@analyses_router.post("/{analysis_id}/like", response_model=LikeOut, response_model_by_alias=True)
async def like_analysis(
    analysis_id: str,
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> LikeOut:
    try:
        aid = uuid.UUID(analysis_id)
    except (ValueError, TypeError):
        raise HTTPException(404, detail="분석 기록을 찾을 수 없습니다.") from None
    if await db.scalar(select(AnalysisResult.id).where(AnalysisResult.id == aid)) is None:
        raise HTTPException(404, detail="분석 기록을 찾을 수 없습니다.")
    dup = await db.scalar(
        select(AnalysisLike.id).where(AnalysisLike.analysis_id == aid, AnalysisLike.user_id == me.id)
    )
    if dup is None:
        db.add(AnalysisLike(analysis_id=aid, user_id=me.id))
        await db.commit()
    return LikeOut(like_count=await _like_count(db, aid), is_liked=True)


@analyses_router.delete("/{analysis_id}/like", response_model=LikeOut, response_model_by_alias=True)
async def unlike_analysis(
    analysis_id: str,
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> LikeOut:
    try:
        aid = uuid.UUID(analysis_id)
    except (ValueError, TypeError):
        raise HTTPException(404, detail="분석 기록을 찾을 수 없습니다.") from None
    row = await db.scalar(
        select(AnalysisLike).where(AnalysisLike.analysis_id == aid, AnalysisLike.user_id == me.id)
    )
    if row is not None:
        await db.delete(row)
        await db.commit()
    return LikeOut(like_count=await _like_count(db, aid), is_liked=False)
