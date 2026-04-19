"""Redis-backed sliding-window rate limiter.

NVD API 제한: 5 req / 30s (keyless), 50 req / 30s (with key).
We use a sliding window via sorted sets — precise but slightly heavier than
a token bucket. Good enough for tens of parsers.
"""
from __future__ import annotations

import asyncio
import time

from redis.asyncio import Redis

from app.core.logging import get_logger

log = get_logger(__name__)


class RateLimiter:
    def __init__(self, redis: Redis, key: str, max_requests: int, window_seconds: float) -> None:
        self.redis = redis
        self.key = f"ratelimit:{key}"
        self.max_requests = max_requests
        self.window_seconds = window_seconds

    async def acquire(self) -> None:
        """Block until a slot is available."""
        while True:
            now = time.time()
            cutoff = now - self.window_seconds

            pipe = self.redis.pipeline()
            pipe.zremrangebyscore(self.key, 0, cutoff)
            pipe.zcard(self.key)
            _, current = await pipe.execute()

            if current < self.max_requests:
                await self.redis.zadd(self.key, {str(now): now})
                await self.redis.expire(self.key, int(self.window_seconds) + 1)
                return

            # Sleep until the oldest slot expires
            oldest = await self.redis.zrange(self.key, 0, 0, withscores=True)
            if oldest:
                _, ts = oldest[0]
                wait = max(0.1, (ts + self.window_seconds) - now)
            else:
                wait = 0.5
            log.debug("rate_limit.wait", key=self.key, wait=round(wait, 2))
            await asyncio.sleep(min(wait, 5.0))
