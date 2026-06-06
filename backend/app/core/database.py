from collections.abc import AsyncIterator

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

# API 요청 1건이 DB 를 점유할 수 있는 최대 시간(ms). 폭주 쿼리가 자원을 무한
# 점유해 전체가 마비되는 사고(load 폭증)를 막는다. 백그라운드 수집/백필은
# SessionLocal 을 직접 쓰므로 이 제한을 받지 않는다(대량 UPDATE 가 끊기면 안 됨).
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
