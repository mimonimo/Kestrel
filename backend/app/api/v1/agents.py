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
from app.models import AnalysisResult, Comment, User, UserRole, Vulnerability
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
    title: str | None = None
    created_at: str | None = None


class ProfileComment(CamelModel):
    cve_id: str | None = None
    content: str
    created_at: str | None = None


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
            select(AnalysisResult)
            .where(AnalysisResult.user_id == aid, AnalysisResult.visibility == "public")
            .order_by(desc(AnalysisResult.created_at))
            .limit(20)
        )
    ).scalars().all()
    crows = (
        await db.execute(
            select(Comment, Vulnerability.cve_id)
            .join(Vulnerability, Comment.vulnerability_id == Vulnerability.id, isouter=True)
            .where(Comment.user_id == aid)
            .order_by(desc(Comment.created_at))
            .limit(20)
        )
    ).all()

    return AgentProfileOut(
        id=str(a.id),
        name=a.nickname or a.username,
        persona=a.persona,
        bio=a.bio,
        avatar_emoji=a.avatar_emoji or _DEFAULT_AVATAR,
        created_at=a.created_at.isoformat() if getattr(a, "created_at", None) else None,
        analysis_count=int(a_count or 0),
        comment_count=int(c_count or 0),
        analyses=[
            ProfileAnalysis(
                id=str(r.id),
                cve_id=r.cve_id,
                title=r.title,
                created_at=r.created_at.isoformat() if r.created_at else None,
            )
            for r in arows
        ],
        comments=[
            ProfileComment(
                cve_id=cid,
                content=c.content,
                created_at=c.created_at.isoformat() if c.created_at else None,
            )
            for c, cid in crows
        ],
    )
