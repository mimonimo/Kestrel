from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings

settings = get_settings()

engine = create_async_engine(
    settings.database_url,
    echo=settings.debug and settings.env == "development",
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
)

SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

# 백그라운드 전용 엔진/풀 — 스케줄러(집계 스냅샷, EPSS 대량 UPDATE 등)와 백필용.
#
# get_db 는 API 요청마다 커넥션에 ``SET statement_timeout = 20s`` 를 건다. 요청이
# 취소(클라이언트 연결 끊김 등)되면 finally 의 RESET 이 스킵되어 20s 타임아웃이
# 풀 커넥션에 남고, 이를 물려받은 백그라운드 잡의 무거운 쿼리가
# ``QueryCanceledError`` 로 잘린다. 게다가 SQLAlchemy 세션은 commit 마다 커넥션을
# 풀에 반납·교체하므로(EPSS 가 TEMP 대신 UNLOGGED 스테이징을 쓰는 이유), 세션
# 레벨로 한 번 ``SET statement_timeout=0`` 을 해도 다음 배치의 새 커넥션엔 적용되지
# 않는다.
#
# → 별도 풀을 두고 connect 시점에 ``statement_timeout=0`` 을 서버 세팅으로 박아
#   둔다. 이 풀의 커넥션은 get_db 를 거치지 않아 20s 누수와 격리되고, 커넥션이
#   교체돼도 항상 무제한이라 대량 작업이 끝까지 돈다.
background_engine = create_async_engine(
    settings.database_url,
    echo=settings.debug and settings.env == "development",
    pool_size=2,
    max_overflow=3,
    pool_pre_ping=True,
    connect_args={"server_settings": {"statement_timeout": "0"}},
)

BackgroundSessionLocal = async_sessionmaker(
    background_engine, expire_on_commit=False, class_=AsyncSession
)

# API 요청 1건이 DB 를 점유할 수 있는 최대 시간(ms). 폭주 쿼리가 자원을 무한
# 점유해 전체가 마비되는 사고(load 폭증)를 막는다. 백그라운드 수집/백필은
# background_session 을 써서 이 제한을 받지 않는다(대량 UPDATE 가 끊기면 안 됨).
_API_STATEMENT_TIMEOUT_MS = 20_000


async def get_db() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        try:
            # 이 요청 동안만 statement_timeout 적용. finally 에서 RESET 해
            # 풀로 반환되는 커넥션이 백그라운드 작업에 영향을 주지 않게 한다.
            await session.execute(
                text(f"SET statement_timeout = {_API_STATEMENT_TIMEOUT_MS}")
            )
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            try:
                await session.execute(text("RESET statement_timeout"))
            except Exception:
                pass


@asynccontextmanager
async def background_session() -> AsyncIterator[AsyncSession]:
    """백그라운드 작업(스케줄러/백필)용 세션.

    statement_timeout 이 0(무제한)으로 고정된 전용 풀에서 세션을 연다. API 풀의
    20s 타임아웃 누수와 격리되며, commit 으로 커넥션이 교체돼도 항상 무제한이다.
    """
    async with BackgroundSessionLocal() as session:
        yield session
