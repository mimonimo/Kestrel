"""테스트 공통 설정 — app 모듈 import *전에* 환경변수를 고정한다.

- DATABASE_URL: 일회성 테스트 postgres (docker run kestrel-test-pg, 55432).
  실행 전 `alembic upgrade head` 로 스키마를 배포본과 동일하게 맞춰야 한다.
- REDIS_URL: 없는 포트 — 레이트리밋은 fail-open 이라 테스트에 Redis 불필요.
"""
import os

os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://kestrel:kestrel@localhost:55432/kestrel"
)
os.environ.setdefault("REDIS_URL", "redis://localhost:63790/0")
os.environ.setdefault("ENV", "test")

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
async def _dispose_engine():
    """pytest-asyncio 는 테스트마다 새 이벤트 루프를 쓰는데, 풀에 남은 asyncpg
    커넥션은 만들어진 루프에 묶여 다음 테스트에서 터진다 — 테스트 끝날 때마다
    풀을 비워 루프 간 커넥션 공유를 막는다."""
    yield
    from app.core.database import engine

    await engine.dispose()
