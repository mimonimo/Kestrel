"""AI 에이전트 관리 — 사용자가 본인 소유의 분석 에이전트(봇)를 등록/관리.

에이전트는 특수 User row(is_agent=true, owner_user_id=현재 사용자)로 저장된다.
분석·게시·댓글은 이 에이전트 user_id 로 귀속돼 기존 커뮤니티/분석 기록에 그대로
노출되고, is_agent 플래그로 🤖 배지를 붙인다. 분석은 소유자의 Claude 크레딧으로
오케스트레이터가 대신 수행한다(Task 4).
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_user
from app.core.database import get_db
from app.core.security import hash_password
from app.models import AnalysisResult, User, UserRole
from app.schemas.vulnerability import CamelModel

router = APIRouter(prefix="/agents", tags=["agents"])

_MAX_AGENTS_PER_USER = 10
_DEFAULT_AVATAR = "🤖"


class AgentCreate(CamelModel):
    name: str = Field(min_length=1, max_length=48)
    persona: str | None = Field(default=None, max_length=64)
    persona_prompt: str | None = Field(default=None, max_length=4000)
    avatar_emoji: str | None = Field(default=None, max_length=16)
    daily_limit: int = Field(default=5, ge=1, le=50)


class AgentUpdate(CamelModel):
    name: str | None = Field(default=None, min_length=1, max_length=48)
    persona: str | None = Field(default=None, max_length=64)
    persona_prompt: str | None = Field(default=None, max_length=4000)
    avatar_emoji: str | None = Field(default=None, max_length=16)
    daily_limit: int | None = Field(default=None, ge=1, le=50)
    enabled: bool | None = None


class AgentOut(CamelModel):
    id: str
    name: str
    persona: str | None = None
    persona_prompt: str | None = None
    avatar_emoji: str | None = None
    enabled: bool = True
    daily_limit: int = 5
    analyses: int = 0
    created_at: str | None = None


def _to_out(u: User, analyses: int = 0) -> AgentOut:
    return AgentOut(
        id=str(u.id),
        name=u.nickname or u.username,
        persona=u.persona,
        persona_prompt=u.persona_prompt,
        avatar_emoji=u.avatar_emoji or _DEFAULT_AVATAR,
        enabled=bool(u.agent_enabled),
        daily_limit=int(u.agent_daily_limit or 5),
        analyses=analyses,
        created_at=u.created_at.isoformat() if getattr(u, "created_at", None) else None,
    )


async def _get_owned_agent(agent_id: str, me: User, db: AsyncSession) -> User:
    try:
        aid = uuid.UUID(agent_id)
    except (ValueError, TypeError):
        raise HTTPException(404, detail="에이전트를 찾을 수 없습니다.") from None
    agent = await db.scalar(select(User).where(User.id == aid, User.is_agent.is_(True)))
    if agent is None or agent.owner_user_id != me.id:
        raise HTTPException(404, detail="에이전트를 찾을 수 없습니다.")
    return agent


@router.get("", response_model=list[AgentOut], response_model_by_alias=True)
async def list_agents(
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[AgentOut]:
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
    return [_to_out(a, int(counts.get(a.id, 0))) for a in agents]


@router.post("", response_model=AgentOut, response_model_by_alias=True, status_code=201)
async def create_agent(
    body: AgentCreate,
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AgentOut:
    n = await db.scalar(
        select(func.count(User.id)).where(
            User.is_agent.is_(True), User.owner_user_id == me.id
        )
    )
    if int(n or 0) >= _MAX_AGENTS_PER_USER:
        raise HTTPException(400, detail=f"에이전트는 최대 {_MAX_AGENTS_PER_USER}개까지 만들 수 있어요.")

    short = uuid.uuid4().hex[:10]
    agent = User(
        email=f"agent+{short}@agents.kestrel.local",
        username=f"agent_{short}",
        password_hash=hash_password(uuid.uuid4().hex),  # 로그인 불가용 무작위 해시
        role=UserRole.USER,
        nickname=body.name.strip()[:48],
        email_verified=True,
        is_agent=True,
        owner_user_id=me.id,
        persona=(body.persona or None),
        persona_prompt=(body.persona_prompt or None),
        avatar_emoji=(body.avatar_emoji or _DEFAULT_AVATAR),
        agent_enabled=True,
        agent_daily_limit=body.daily_limit,
    )
    db.add(agent)
    await db.commit()
    await db.refresh(agent)
    return _to_out(agent)


@router.patch("/{agent_id}", response_model=AgentOut, response_model_by_alias=True)
async def update_agent(
    agent_id: str,
    body: AgentUpdate,
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AgentOut:
    agent = await _get_owned_agent(agent_id, me, db)
    if body.name is not None:
        agent.nickname = body.name.strip()[:48]
    if body.persona is not None:
        agent.persona = body.persona or None
    if body.persona_prompt is not None:
        agent.persona_prompt = body.persona_prompt or None
    if body.avatar_emoji is not None:
        agent.avatar_emoji = body.avatar_emoji or _DEFAULT_AVATAR
    if body.daily_limit is not None:
        agent.agent_daily_limit = body.daily_limit
    if body.enabled is not None:
        agent.agent_enabled = body.enabled
    await db.commit()
    await db.refresh(agent)
    return _to_out(agent)


@router.delete("/{agent_id}", status_code=204)
async def delete_agent(
    agent_id: str,
    me: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    agent = await _get_owned_agent(agent_id, me, db)
    await db.delete(agent)
    await db.commit()


@router.post("/run", status_code=202)
async def run_now(
    bg: BackgroundTasks,
    me: User = Depends(get_current_user),
) -> dict:
    """에이전트 자동 분석 사이클을 즉시 1회 백그라운드 실행(테스트/수동 트리거)."""
    from app.services.agent_orchestrator import run_agent_cycle

    bg.add_task(run_agent_cycle)
    return {
        "ok": True,
        "message": "에이전트 분석 사이클을 시작했습니다. 잠시 후 커뮤니티·분석 기록에 결과가 올라옵니다.",
    }
