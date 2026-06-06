"""인증 엔드포인트용 경량 rate limit (Redis 고정 윈도우).

설계 원칙:
- **로그인**은 *실패* 횟수만 카운트한다. 성공하면 카운터를 지워, 정상 사용자가
  자주 로그인해도 잠기지 않게 한다. IP 와 이메일 두 축으로 막아 스프레이(한 IP가
  여러 계정 시도)와 타깃 브루트포스(한 계정에 다수 시도)를 모두 차단.
- **가입**은 모든 시도를 IP 기준으로 카운트 — 대량 계정 생성/스팸 억제.
- **Fail-open**: Redis 가 죽으면 인증을 막지 않는다(가용성 우선). 단 차단 자체는
  best-effort. 카운트 키는 TTL 로 자동 정리.

주의: 여기서 받는 식별자(email/IP)는 로그나 예외 메시지에 그대로 노출하지 않는다.
"""
from __future__ import annotations

import structlog
from fastapi import HTTPException, status

from app.core.redis_client import get_redis

log = structlog.get_logger(__name__)

# 로그인 실패 임계치
_LOGIN_EMAIL_LIMIT = 5      # 동일 이메일 실패 5회
_LOGIN_IP_LIMIT = 20        # 동일 IP 실패 20회 (스프레이)
_LOGIN_WINDOW = 15 * 60     # 15분

# 가입 시도 임계치 (IP 기준)
_SIGNUP_IP_LIMIT = 10
_SIGNUP_WINDOW = 60 * 60    # 1시간

# 이메일 발송(인증 재발송 / 비밀번호 찾기) 임계치 — 메일 폭탄/열거 억제.
_EMAIL_IP_LIMIT = 10        # 동일 IP 1시간 10통
_EMAIL_ADDR_LIMIT = 5       # 동일 수신 이메일 1시간 5통
_EMAIL_WINDOW = 60 * 60


def _too_many(retry_after: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.",
        headers={"Retry-After": str(max(retry_after, 1))},
    )


async def _count(key: str, window: int) -> int:
    """키를 1 증가시키고 현재 카운트 반환. 최초 증가 시 TTL 설정."""
    redis = await get_redis()
    cnt = await redis.incr(key)
    if cnt == 1:
        await redis.expire(key, window)
    return int(cnt)


async def _current(key: str) -> int:
    redis = await get_redis()
    val = await redis.get(key)
    return int(val) if val else 0


# ─── 로그인 ──────────────────────────────────────────────
def _login_email_key(email: str) -> str:
    return f"rl:login:email:{email}"


def _login_ip_key(ip: str) -> str:
    return f"rl:login:ip:{ip}"


async def enforce_login_rate_limit(ip: str, email: str) -> None:
    """현재까지 누적된 *실패* 가 임계치를 넘었으면 429. (실패 기록은 별도 함수)"""
    try:
        email_fails = await _current(_login_email_key(email))
        ip_fails = await _current(_login_ip_key(ip))
    except Exception as exc:  # noqa: BLE001 — Redis 장애 시 인증 막지 않음
        log.warning("rate_limit_check_failed", scope="login", error=str(exc))
        return
    if email_fails >= _LOGIN_EMAIL_LIMIT or ip_fails >= _LOGIN_IP_LIMIT:
        raise _too_many(_LOGIN_WINDOW)


async def record_login_failure(ip: str, email: str) -> None:
    try:
        await _count(_login_email_key(email), _LOGIN_WINDOW)
        await _count(_login_ip_key(ip), _LOGIN_WINDOW)
    except Exception as exc:  # noqa: BLE001
        log.warning("rate_limit_record_failed", scope="login", error=str(exc))


async def reset_login_failures(ip: str, email: str) -> None:
    """로그인 성공 시 호출 — 정상 사용자가 잠기지 않도록 실패 카운터 제거."""
    try:
        redis = await get_redis()
        await redis.delete(_login_email_key(email), _login_ip_key(ip))
    except Exception as exc:  # noqa: BLE001
        log.warning("rate_limit_reset_failed", scope="login", error=str(exc))


# ─── 가입 ────────────────────────────────────────────────
async def enforce_signup_rate_limit(ip: str) -> None:
    try:
        cnt = await _count(f"rl:signup:ip:{ip}", _SIGNUP_WINDOW)
    except Exception as exc:  # noqa: BLE001
        log.warning("rate_limit_check_failed", scope="signup", error=str(exc))
        return
    if cnt > _SIGNUP_IP_LIMIT:
        raise _too_many(_SIGNUP_WINDOW)


# ─── 이메일 발송 (인증 재발송 / 비밀번호 찾기) ───────────
async def enforce_email_send_rate_limit(ip: str, email: str) -> None:
    """메일 발송 트리거 엔드포인트 보호 — IP·수신주소 두 축으로 카운트.

    forgot-password 는 계정 존재 여부와 무관하게 항상 200 을 주지만, 그렇다고
    무제한 발송하면 메일 폭탄/열거에 악용된다. 시도 자체를 카운트한다."""
    try:
        ip_cnt = await _count(f"rl:email:ip:{ip}", _EMAIL_WINDOW)
        addr_cnt = await _count(f"rl:email:addr:{email}", _EMAIL_WINDOW)
    except Exception as exc:  # noqa: BLE001 — Redis 장애 시 막지 않음
        log.warning("rate_limit_check_failed", scope="email", error=str(exc))
        return
    if ip_cnt > _EMAIL_IP_LIMIT or addr_cnt > _EMAIL_ADDR_LIMIT:
        raise _too_many(_EMAIL_WINDOW)
