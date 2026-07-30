"""작성자(사용자/에이전트) 구독 API.

구독한 작성자가 새 공개 분석 또는 커뮤니티 글을 발행하면, 구독자 본인의
알림채널(Slack/Discord 웹훅)로 전달된다(전달 로직은
``services.notifications.notify_author_subscribers``). 여기서는 구독 관계의
CRUD 만 담당하며 모두 로그인 필수.

작성자 식별은 내부 ``user_id`` 대신 **username** 으로 한다 — 분석 기록 API
(``AuthorOut``)가 이미 username/nickname 만 노출하고 user_id 는 감추는 관례를
따른다. username 은 유일·불변 식별자라 구독 키로 적합.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_user
from app.core.database import get_db
from app.models import AuthorSubscription, User
from app.schemas.vulnerability import CamelModel

router = APIRouter(prefix="/subscriptions", tags=["subscriptions"])


def _author_name(u: User) -> str:
    return u.persona or u.nickname or u.username or "익명"


class SubscribeRequest(CamelModel):
    username: str


class SubscribedAuthor(CamelModel):
    username: str
    name: str
    is_agent: bool


class SubscriptionsResponse(CamelModel):
    items: list[SubscribedAuthor]


@router.get("", response_model=SubscriptionsResponse, response_model_by_alias=True)
async def list_subscriptions(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SubscriptionsResponse:
    """내가 구독 중인 작성자 목록 (최신 구독 순)."""
    rows = (
        await db.execute(
            select(User)
            .join(AuthorSubscription, AuthorSubscription.author_user_id == User.id)
            .where(AuthorSubscription.subscriber_user_id == user.id)
            .order_by(AuthorSubscription.created_at.desc())
        )
    ).scalars().all()
    return SubscriptionsResponse(
        items=[
            SubscribedAuthor(username=u.username, name=_author_name(u), is_agent=bool(u.is_agent))
            for u in rows
        ]
    )


@router.post("", status_code=status.HTTP_201_CREATED)
async def subscribe(
    body: SubscribeRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """작성자 구독(username 기준). 자기 자신 금지, 없는 작성자 404, 중복 무시(멱등)."""
    author = await db.scalar(select(User).where(User.username == body.username))
    if author is None:
        raise HTTPException(status_code=404, detail="존재하지 않는 작성자입니다.")
    if author.id == user.id:
        raise HTTPException(status_code=400, detail="자기 자신은 구독할 수 없습니다.")
    stmt = (
        pg_insert(AuthorSubscription)
        .values(subscriber_user_id=user.id, author_user_id=author.id)
        .on_conflict_do_nothing(index_elements=["subscriber_user_id", "author_user_id"])
    )
    await db.execute(stmt)
    await db.commit()
    return {"subscribed": True}


@router.delete("/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def unsubscribe(
    username: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """구독 해제(username 기준). 없던 구독이면 no-op(204)."""
    author = await db.scalar(select(User).where(User.username == username))
    if author is None:
        return  # 없는 작성자 → 지울 것도 없음
    await db.execute(
        delete(AuthorSubscription).where(
            AuthorSubscription.subscriber_user_id == user.id,
            AuthorSubscription.author_user_id == author.id,
        )
    )
    await db.commit()
