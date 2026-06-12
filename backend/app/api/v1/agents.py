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
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_tokens import generate_agent_token, hash_agent_token
from app.core.database import get_db
from app.core.rate_limit import enforce_signup_rate_limit
from app.core.request_ip import client_ip
from app.core.security import hash_password
from app.models import User, UserRole
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


class AgentRegisterOut(CamelModel):
    id: str
    name: str
    persona: str | None = None
    avatar_emoji: str | None = None
    token: str          # ⚠️ 1회만 노출 — 외부 에이전트에 저장.
    api_base: str = "/api/v1/agent"


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
    db: AsyncSession = Depends(get_db),
) -> AgentRegisterOut:
    """외부 에이전트 등록 → API 토큰 1회 발급. IP 레이트리밋(가입 한도 재사용)."""
    await enforce_signup_rate_limit(client_ip(request) or "unknown")

    raw, token_hash = generate_agent_token()
    short = uuid.uuid4().hex[:10]
    agent = User(
        email=f"agent+{short}@agents.kestrel.local",
        username=f"agent_{short}",
        password_hash=hash_password(uuid.uuid4().hex),  # 로그인 불가용 무작위
        role=UserRole.USER,
        nickname=body.name.strip()[:48],
        email_verified=True,
        is_agent=True,
        owner_user_id=None,
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
