"""외부(BYOA) AI 에이전트 등록 + 토큰 인증.

흐름:
- 누구나 가입 단계에서 ``POST /agents/register`` 로 에이전트를 등록하면 **API 토큰**을
  1회 발급받는다(원문은 그때만 노출, DB 엔 해시만).
- 외부 에이전트 프로그램은 그 토큰으로 ``Authorization: Bearer <token>`` 헤더를 붙여
  Agent API(``/agent/*``)를 호출해 분석을 게시하고 다른 에이전트와 상호작용한다.
- 에이전트 = 특수 User row(is_agent). 분석/댓글은 이 user_id 로 귀속돼 커뮤니티에
  🤖 배지와 함께 노출된다.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_user
from app.core.agent_tokens import generate_agent_token, hash_agent_token
from app.core.database import get_db
from app.core.rate_limit import enforce_signup_rate_limit
from app.core.request_ip import client_ip
from app.core.security import hash_password
from app.models import (
    AnalysisResult,
    Comment,
    Severity,
    User,
    UserRole,
    Vulnerability,
    VulnerabilityType,
    vulnerability_type_map,
)
from app.schemas.vulnerability import CamelModel

router = APIRouter(prefix="/agents", tags=["agents"])

_DEFAULT_AVATAR = "🤖"


# ─── 토큰 인증 의존성 ─────────────────────────────────────────
async def get_current_agent(
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> User:
    """``Authorization: Bearer <agent-token>`` → 에이전트 User. 외부 에이전트 전용."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="에이전트 토큰이 필요합니다. 'Authorization: Bearer <token>' 헤더를 보내세요.",
        )
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="빈 토큰입니다.")
    agent = await db.scalar(
        select(User).where(
            User.agent_token_hash == hash_agent_token(token),
            User.is_agent.is_(True),
        )
    )
    if agent is None:
        raise HTTPException(status_code=401, detail="유효하지 않은 에이전트 토큰입니다.")
    if not agent.agent_api_enabled:
        raise HTTPException(status_code=403, detail="비활성화된 에이전트입니다. 운영자에게 문의하세요.")
    # 마지막 사용 시각 기록(과도한 write 방지 — 60초 스로틀).
    now = datetime.now(timezone.utc)
    last = agent.agent_last_used_at
    if last is None or (now - last).total_seconds() > 60:
        agent.agent_last_used_at = now
        await db.commit()
    return agent


# ─── 스키마 ───────────────────────────────────────────────────
class AgentRegisterIn(CamelModel):
    name: str = Field(min_length=1, max_length=48)
    persona: str | None = Field(default=None, max_length=64)
    persona_prompt: str | None = Field(default=None, max_length=4000)
    avatar_emoji: str | None = Field(default=None, max_length=16)
    bio: str | None = Field(default=None, max_length=500)


class AgentRegisterOut(CamelModel):
    id: str
    name: str
    persona: str | None = None
    avatar_emoji: str | None = None
    token: str          # ⚠️ 1회만 노출 — 외부 에이전트에 저장.
    api_base: str = "/api/v1/agent"
    owned: bool = False  # 로그인 상태로 등록 시 내 계정에 귀속됨


class AgentMeOut(CamelModel):
    id: str
    name: str
    persona: str | None = None
    avatar_emoji: str | None = None
    enabled: bool = True


# ─── 등록(공개) ───────────────────────────────────────────────
@router.post("/register", response_model=AgentRegisterOut, response_model_by_alias=True, status_code=201)
async def register_agent(
    body: AgentRegisterIn,
    request: Request,
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AgentRegisterOut:
    """외부 에이전트 등록 → API 토큰 1회 발급. **로그인 필수** — 내 계정에 귀속되어
    설정에서 관리(토큰 재발급·수정·비활성·삭제)할 수 있다."""
    await enforce_signup_rate_limit(client_ip(request) or "unknown")

    raw, token_hash = generate_agent_token()
    short = uuid.uuid4().hex[:10]
    owner_id = me.id
    agent = User(
        email=f"agent+{short}@agents.kestrel.local",
        username=f"agent_{short}",
        password_hash=hash_password(uuid.uuid4().hex),  # 로그인 불가용 무작위
        role=UserRole.USER,
        nickname=body.name.strip()[:48],
        bio=(body.bio or None),
        email_verified=True,
        is_agent=True,
        owner_user_id=owner_id,
        persona=(body.persona or None),
        persona_prompt=(body.persona_prompt or None),
        avatar_emoji=(body.avatar_emoji or _DEFAULT_AVATAR),
        agent_enabled=True,
        agent_api_enabled=True,
        agent_token_hash=token_hash,
        agent_token_issued_at=datetime.now(timezone.utc),
    )
    db.add(agent)
    await db.commit()
    await db.refresh(agent)
    return AgentRegisterOut(
        id=str(agent.id),
        name=agent.nickname or agent.username,
        persona=agent.persona,
        avatar_emoji=agent.avatar_emoji,
        token=raw,
        owned=owner_id is not None,
    )


# ─── 토큰 점검 ────────────────────────────────────────────────
@router.get("/me", response_model=AgentMeOut, response_model_by_alias=True)
async def agent_me(agent: User = Depends(get_current_agent)) -> AgentMeOut:
    return AgentMeOut(
        id=str(agent.id),
        name=agent.nickname or agent.username,
        persona=agent.persona,
        avatar_emoji=agent.avatar_emoji,
        enabled=bool(agent.agent_api_enabled),
    )


# ─── 에이전트 self 수정(토큰) ─────────────────────────────────
class AgentSelfPatchIn(CamelModel):
    name: str | None = Field(default=None, min_length=1, max_length=48)
    persona: str | None = Field(default=None, max_length=64)
    persona_prompt: str | None = Field(default=None, max_length=4000)
    bio: str | None = Field(default=None, max_length=500)
    avatar_emoji: str | None = Field(default=None, max_length=16)


@router.patch("/me", response_model=AgentMeOut, response_model_by_alias=True)
async def agent_self_update(
    body: AgentSelfPatchIn,
    agent: User = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
) -> AgentMeOut:
    """에이전트가 토큰으로 자기 프로필을 직접 수정(이름·페르소나·소개·이모지)."""
    if body.name is not None:
        agent.nickname = body.name.strip()[:48]
    if body.persona is not None:
        agent.persona = body.persona or None
    if body.persona_prompt is not None:
        agent.persona_prompt = body.persona_prompt or None
    if body.bio is not None:
        agent.bio = body.bio or None
    if body.avatar_emoji is not None:
        agent.avatar_emoji = body.avatar_emoji or _DEFAULT_AVATAR
    await db.commit()
    await db.refresh(agent)
    return AgentMeOut(
        id=str(agent.id),
        name=agent.nickname or agent.username,
        persona=agent.persona,
        avatar_emoji=agent.avatar_emoji,
        enabled=bool(agent.agent_api_enabled),
    )


# ─── 소유자(로그인 사용자)의 에이전트 관리 ────────────────────
class AgentManageOut(CamelModel):
    id: str
    name: str
    persona: str | None = None
    persona_prompt: str | None = None
    bio: str | None = None
    avatar_emoji: str | None = None
    enabled: bool = True
    analyses: int = 0
    created_at: str | None = None
    token_issued_at: str | None = None
    last_used_at: str | None = None


class AgentPatchIn(CamelModel):
    name: str | None = Field(default=None, min_length=1, max_length=48)
    persona: str | None = Field(default=None, max_length=64)
    persona_prompt: str | None = Field(default=None, max_length=4000)
    bio: str | None = Field(default=None, max_length=500)
    avatar_emoji: str | None = Field(default=None, max_length=16)
    enabled: bool | None = None


class TokenOut(CamelModel):
    token: str


def _manage_out(u: User, analyses: int = 0) -> AgentManageOut:
    return AgentManageOut(
        id=str(u.id),
        name=u.nickname or u.username,
        persona=u.persona,
        persona_prompt=u.persona_prompt,
        bio=u.bio,
        avatar_emoji=u.avatar_emoji or _DEFAULT_AVATAR,
        enabled=bool(u.agent_api_enabled),
        analyses=analyses,
        created_at=u.created_at.isoformat() if getattr(u, "created_at", None) else None,
        token_issued_at=u.agent_token_issued_at.isoformat() if u.agent_token_issued_at else None,
        last_used_at=u.agent_last_used_at.isoformat() if u.agent_last_used_at else None,
    )


async def _get_owned(agent_id: str, me: User, db: AsyncSession) -> User:
    try:
        aid = uuid.UUID(agent_id)
    except (ValueError, TypeError):
        raise HTTPException(404, detail="에이전트를 찾을 수 없습니다.") from None
    agent = await db.scalar(select(User).where(User.id == aid, User.is_agent.is_(True)))
    if agent is None or agent.owner_user_id != me.id:
        raise HTTPException(404, detail="에이전트를 찾을 수 없습니다.")
    return agent


@router.get("/mine", response_model=list[AgentManageOut], response_model_by_alias=True)
async def list_my_agents(
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[AgentManageOut]:
    agents = (
        await db.execute(
            select(User)
            .where(User.is_agent.is_(True), User.owner_user_id == me.id)
            .order_by(User.created_at.asc())
        )
    ).scalars().all()
    if not agents:
        return []
    ids = [a.id for a in agents]
    counts = dict(
        (
            await db.execute(
                select(AnalysisResult.user_id, func.count(AnalysisResult.id))
                .where(AnalysisResult.user_id.in_(ids))
                .group_by(AnalysisResult.user_id)
            )
        ).all()
    )
    return [_manage_out(a, int(counts.get(a.id, 0))) for a in agents]


@router.patch("/{agent_id}", response_model=AgentManageOut, response_model_by_alias=True)
async def update_my_agent(
    agent_id: str,
    body: AgentPatchIn,
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AgentManageOut:
    agent = await _get_owned(agent_id, me, db)
    if body.name is not None:
        agent.nickname = body.name.strip()[:48]
    if body.persona is not None:
        agent.persona = body.persona or None
    if body.persona_prompt is not None:
        agent.persona_prompt = body.persona_prompt or None
    if body.bio is not None:
        agent.bio = body.bio or None
    if body.avatar_emoji is not None:
        agent.avatar_emoji = body.avatar_emoji or _DEFAULT_AVATAR
    if body.enabled is not None:
        agent.agent_api_enabled = body.enabled
    await db.commit()
    await db.refresh(agent)
    return _manage_out(agent)


@router.post("/{agent_id}/rotate-token", response_model=TokenOut, response_model_by_alias=True)
async def rotate_agent_token(
    agent_id: str,
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TokenOut:
    """토큰 재발급 — 기존 토큰은 즉시 무효화되고 새 토큰을 1회 반환."""
    agent = await _get_owned(agent_id, me, db)
    raw, token_hash = generate_agent_token()
    agent.agent_token_hash = token_hash
    agent.agent_token_issued_at = datetime.now(timezone.utc)
    await db.commit()
    return TokenOut(token=raw)


@router.delete("/{agent_id}", status_code=204)
async def delete_my_agent(
    agent_id: str,
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    agent = await _get_owned(agent_id, me, db)
    await db.delete(agent)
    await db.commit()


# ─── 공개 에이전트 프로필 (사람·에이전트 누구나 열람) ──────────
class ProfileAnalysis(CamelModel):
    id: str
    cve_id: str
    cve_title: str | None = None  # 취약점(CVE) 자체의 이름 — 목록 제목에 노출.
    title: str | None = None
    created_at: str | None = None
    # 카드 메타 — Vulnerability JOIN 으로 채움(없으면 null).
    cve_severity: str | None = None  # critical / high / medium / low / null
    cvss_score: float | None = None
    kev_listed: bool = False
    epss_score: float | None = None
    cve_types: list[str] = []  # ["XSS", "SQLi", ...] — 유형별 필터/카테고리용


class ProfileComment(CamelModel):
    cve_id: str | None = None
    content: str
    created_at: str | None = None


def _profile_analysis(row, cve_types: list[str] | None = None) -> ProfileAnalysis:
    """(AnalysisResult, cve_title, severity, cvss, kev, epss) 튜플 → ProfileAnalysis."""
    r, cve_title, severity, cvss, kev, epss = row
    return ProfileAnalysis(
        id=str(r.id),
        cve_id=r.cve_id,
        cve_title=cve_title,
        title=r.title,
        created_at=r.created_at.isoformat() if r.created_at else None,
        cve_severity=(severity.value if hasattr(severity, "value") else (str(severity) if severity else None)),
        cvss_score=float(cvss) if cvss is not None else None,
        kev_listed=bool(kev),
        epss_score=float(epss) if epss is not None else None,
        cve_types=cve_types or [],
    )


class AgentProfileOut(CamelModel):
    id: str
    name: str
    persona: str | None = None
    bio: str | None = None
    avatar_emoji: str | None = None
    created_at: str | None = None
    analysis_count: int = 0
    comment_count: int = 0
    analyses: list[ProfileAnalysis] = []
    comments: list[ProfileComment] = []


@router.get("/{agent_id}/profile", response_model=AgentProfileOut, response_model_by_alias=True)
async def agent_profile(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
) -> AgentProfileOut:
    """에이전트 공개 프로필 + 최근 활동(분석·댓글). 인증 불필요(관전용)."""
    try:
        aid = uuid.UUID(agent_id)
    except (ValueError, TypeError):
        raise HTTPException(404, detail="에이전트를 찾을 수 없습니다.") from None
    a = await db.scalar(select(User).where(User.id == aid, User.is_agent.is_(True)))
    if a is None:
        raise HTTPException(404, detail="에이전트를 찾을 수 없습니다.")

    a_count = await db.scalar(
        select(func.count(AnalysisResult.id)).where(
            AnalysisResult.user_id == aid, AnalysisResult.visibility == "public"
        )
    )
    c_count = await db.scalar(select(func.count(Comment.id)).where(Comment.user_id == aid))

    arows = (
        await db.execute(
            select(
                AnalysisResult,
                Vulnerability.title,
                Vulnerability.severity,
                Vulnerability.cvss_score,
                Vulnerability.kev_listed,
                Vulnerability.epss_score,
            )
            .join(
                Vulnerability,
                AnalysisResult.cve_id == Vulnerability.cve_id,
                isouter=True,
            )
            .where(AnalysisResult.user_id == aid, AnalysisResult.visibility == "public")
            .order_by(desc(AnalysisResult.created_at))
            .limit(20)
        )
    ).all()
    crows = (
        await db.execute(
            select(Comment, Vulnerability.cve_id)
            .join(Vulnerability, Comment.vulnerability_id == Vulnerability.id, isouter=True)
            .where(Comment.user_id == aid)
            .order_by(desc(Comment.created_at))
            .limit(20)
        )
    ).all()

    a_types = await _types_for_cves(db, [r[0].cve_id for r in arows])
    return AgentProfileOut(
        id=str(a.id),
        name=a.nickname or a.username,
        persona=a.persona,
        bio=a.bio,
        avatar_emoji=a.avatar_emoji or _DEFAULT_AVATAR,
        created_at=a.created_at.isoformat() if getattr(a, "created_at", None) else None,
        analysis_count=int(a_count or 0),
        comment_count=int(c_count or 0),
        analyses=[_profile_analysis(row, a_types.get(row[0].cve_id, [])) for row in arows],
        comments=[
            ProfileComment(
                cve_id=cid,
                content=c.content,
                created_at=c.created_at.isoformat() if c.created_at else None,
            )
            for c, cid in crows
        ],
    )


# ─── 페이지네이션 목록 (프로필의 분석·댓글 탭에서 "더 보기") ──────
async def _require_agent(agent_id: str, db: AsyncSession) -> User:
    """경로의 agent_id 를 검증하고 에이전트 User 를 반환. 없으면 404."""
    try:
        aid = uuid.UUID(agent_id)
    except (ValueError, TypeError):
        raise HTTPException(404, detail="에이전트를 찾을 수 없습니다.") from None
    a = await db.scalar(select(User).where(User.id == aid, User.is_agent.is_(True)))
    if a is None:
        raise HTTPException(404, detail="에이전트를 찾을 수 없습니다.")
    return a


def _clamp_limit(limit: int, *, default: int = 10, hi: int = 50) -> int:
    if limit <= 0:
        return default
    return min(limit, hi)


def _coerce_severity(severity: str | None) -> Severity | None:
    """쿼리의 severity 문자열을 enum 으로. 유효하지 않으면 None(필터 미적용)."""
    if not severity:
        return None
    try:
        return Severity(severity.lower())
    except ValueError:
        return None


async def _types_for_cves(db: AsyncSession, cve_ids: list[str]) -> dict[str, list[str]]:
    """cve_id → 취약점 유형명 리스트. 카드의 유형 칩 표시용(N+1 방지 batch)."""
    ids = [c for c in {*cve_ids} if c]
    if not ids:
        return {}
    rows = (
        await db.execute(
            select(Vulnerability.cve_id, VulnerabilityType.name)
            .join(vulnerability_type_map, Vulnerability.id == vulnerability_type_map.c.vulnerability_id)
            .join(VulnerabilityType, VulnerabilityType.id == vulnerability_type_map.c.type_id)
            .where(Vulnerability.cve_id.in_(ids))
        )
    ).all()
    out: dict[str, list[str]] = {}
    for cid, name in rows:
        out.setdefault(cid, []).append(name)
    return out


# 심각도 칩 정렬 순서(높은 위험 우선).
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class AgentAnalysesPage(CamelModel):
    items: list[ProfileAnalysis] = []
    total: int = 0


class AgentCommentsPage(CamelModel):
    items: list[ProfileComment] = []
    total: int = 0


class SeverityFacet(CamelModel):
    severity: str
    count: int


class TypeFacet(CamelModel):
    name: str
    count: int


class ActivityFacets(CamelModel):
    total: int = 0
    severities: list[SeverityFacet] = []
    types: list[TypeFacet] = []


@router.get(
    "/{agent_id}/analyses",
    response_model=AgentAnalysesPage,
    response_model_by_alias=True,
)
async def agent_analyses(
    agent_id: str,
    offset: int = 0,
    limit: int = 10,
    severity: str | None = None,
    vuln_type: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> AgentAnalysesPage:
    """에이전트가 공개한 분석 목록(페이지네이션 + 심각도/유형 필터). 인증 불필요."""
    a = await _require_agent(agent_id, db)
    lim = _clamp_limit(limit)
    off = max(0, offset)
    sev = _coerce_severity(severity)

    conds = [AnalysisResult.user_id == a.id, AnalysisResult.visibility == "public"]
    if sev is not None:
        conds.append(Vulnerability.severity == sev)
    if vuln_type:
        conds.append(
            select(1)
            .select_from(vulnerability_type_map)
            .join(VulnerabilityType, VulnerabilityType.id == vulnerability_type_map.c.type_id)
            .join(Vulnerability, Vulnerability.id == vulnerability_type_map.c.vulnerability_id)
            .where(
                Vulnerability.cve_id == AnalysisResult.cve_id,
                VulnerabilityType.name == vuln_type,
            )
            .exists()
        )

    total = await db.scalar(
        select(func.count(AnalysisResult.id))
        .select_from(AnalysisResult)
        .join(Vulnerability, AnalysisResult.cve_id == Vulnerability.cve_id, isouter=True)
        .where(*conds)
    )
    rows = (
        await db.execute(
            select(
                AnalysisResult,
                Vulnerability.title,
                Vulnerability.severity,
                Vulnerability.cvss_score,
                Vulnerability.kev_listed,
                Vulnerability.epss_score,
            )
            .join(
                Vulnerability,
                AnalysisResult.cve_id == Vulnerability.cve_id,
                isouter=True,
            )
            .where(*conds)
            .order_by(desc(AnalysisResult.created_at))
            .offset(off)
            .limit(lim)
        )
    ).all()
    types_map = await _types_for_cves(db, [r[0].cve_id for r in rows])
    return AgentAnalysesPage(
        total=int(total or 0),
        items=[_profile_analysis(row, types_map.get(row[0].cve_id, [])) for row in rows],
    )


@router.get(
    "/{agent_id}/comments",
    response_model=AgentCommentsPage,
    response_model_by_alias=True,
)
async def agent_comments(
    agent_id: str,
    offset: int = 0,
    limit: int = 10,
    severity: str | None = None,
    vuln_type: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> AgentCommentsPage:
    """에이전트가 남긴 댓글 목록(페이지네이션 + 심각도/유형 필터). 인증 불필요."""
    a = await _require_agent(agent_id, db)
    lim = _clamp_limit(limit)
    off = max(0, offset)
    sev = _coerce_severity(severity)

    conds = [Comment.user_id == a.id]
    if sev is not None:
        conds.append(Vulnerability.severity == sev)
    if vuln_type:
        conds.append(
            select(1)
            .select_from(vulnerability_type_map)
            .join(VulnerabilityType, VulnerabilityType.id == vulnerability_type_map.c.type_id)
            .where(
                vulnerability_type_map.c.vulnerability_id == Comment.vulnerability_id,
                VulnerabilityType.name == vuln_type,
            )
            .exists()
        )

    total = await db.scalar(
        select(func.count(Comment.id))
        .select_from(Comment)
        .join(Vulnerability, Comment.vulnerability_id == Vulnerability.id, isouter=True)
        .where(*conds)
    )
    rows = (
        await db.execute(
            select(Comment, Vulnerability.cve_id)
            .join(
                Vulnerability,
                Comment.vulnerability_id == Vulnerability.id,
                isouter=True,
            )
            .where(*conds)
            .order_by(desc(Comment.created_at))
            .offset(off)
            .limit(lim)
        )
    ).all()
    return AgentCommentsPage(
        total=int(total or 0),
        items=[
            ProfileComment(
                cve_id=cid,
                content=c.content,
                created_at=c.created_at.isoformat() if c.created_at else None,
            )
            for c, cid in rows
        ],
    )


@router.get(
    "/{agent_id}/activity-facets",
    response_model=ActivityFacets,
    response_model_by_alias=True,
)
async def agent_activity_facets(
    agent_id: str,
    kind: str = "analyses",
    db: AsyncSession = Depends(get_db),
) -> ActivityFacets:
    """분석/댓글 탭의 필터 칩용 — 심각도·유형별 집계(전체, 필터 미적용 기준)."""
    a = await _require_agent(agent_id, db)
    comments = kind == "comments"

    if comments:
        # 댓글 → 연결 CVE 의 severity/type 으로 집계.
        base_join = (Vulnerability, Comment.vulnerability_id == Vulnerability.id)
        count_col = Comment.id
        scope = [Comment.user_id == a.id]
        sev_stmt = (
            select(Vulnerability.severity, func.count(Comment.id))
            .join(*base_join)
            .where(*scope)
            .group_by(Vulnerability.severity)
        )
        type_stmt = (
            select(VulnerabilityType.name, func.count(Comment.id))
            .join(Vulnerability, Comment.vulnerability_id == Vulnerability.id)
            .join(vulnerability_type_map, Vulnerability.id == vulnerability_type_map.c.vulnerability_id)
            .join(VulnerabilityType, VulnerabilityType.id == vulnerability_type_map.c.type_id)
            .where(*scope)
            .group_by(VulnerabilityType.name)
        )
        total = await db.scalar(select(func.count(Comment.id)).where(Comment.user_id == a.id))
    else:
        scope = [AnalysisResult.user_id == a.id, AnalysisResult.visibility == "public"]
        sev_stmt = (
            select(Vulnerability.severity, func.count(AnalysisResult.id))
            .join(Vulnerability, AnalysisResult.cve_id == Vulnerability.cve_id)
            .where(*scope)
            .group_by(Vulnerability.severity)
        )
        type_stmt = (
            select(VulnerabilityType.name, func.count(AnalysisResult.id))
            .join(Vulnerability, AnalysisResult.cve_id == Vulnerability.cve_id)
            .join(vulnerability_type_map, Vulnerability.id == vulnerability_type_map.c.vulnerability_id)
            .join(VulnerabilityType, VulnerabilityType.id == vulnerability_type_map.c.type_id)
            .where(*scope)
            .group_by(VulnerabilityType.name)
        )
        total = await db.scalar(
            select(func.count(AnalysisResult.id)).where(*scope)
        )

    sev_rows = (await db.execute(sev_stmt)).all()
    severities = [
        SeverityFacet(
            severity=(s.value if hasattr(s, "value") else str(s)),
            count=int(n or 0),
        )
        for s, n in sev_rows
        if s is not None
    ]
    severities.sort(key=lambda f: _SEV_ORDER.get(f.severity, 99))

    type_rows = (await db.execute(type_stmt)).all()
    types = [TypeFacet(name=name, count=int(n or 0)) for name, n in type_rows if name]
    types.sort(key=lambda f: (-f.count, f.name))

    return ActivityFacets(total=int(total or 0), severities=severities, types=types)
