"""운영 알림 발행 — SNS 토픽으로 메시지를 보낸다(관리자 이메일 구독).

설계:
- ``alerts_sns_topic_arn`` 미설정이면 아무것도 하지 않는다(no-op) — 로컬/개발에서
  SNS 없이도 호출부가 안전하게 동작.
- boto3 는 동기라 ``asyncio.to_thread`` 로 감싸 이벤트 루프를 막지 않는다.
- 인스턴스 IAM 역할 자격증명을 자동 사용(정적 키 불필요).
- 발행 실패는 호출부 흐름을 막지 않도록 예외를 잡아 로깅만 한다.
"""
from __future__ import annotations

import asyncio
from functools import lru_cache

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)


@lru_cache
def _sns_client():  # noqa: ANN202 — boto3 client 타입
    import boto3  # 지연 import — 토픽 미설정이면 boto3 미사용

    return boto3.client("sns", region_name=get_settings().aws_region)


async def publish_alert(subject: str, message: str) -> bool:
    """알림 토픽으로 메시지 발행. 성공 시 True, 미설정/실패 시 False."""
    arn = get_settings().alerts_sns_topic_arn
    if not arn:
        log.info("notify.skipped_no_topic", subject=subject)
        return False

    # SNS subject 는 100자 + ASCII 제한이 있어 안전하게 자른다.
    safe_subject = (subject or "Kestrel 알림")[:100]

    def _do() -> None:
        _sns_client().publish(TopicArn=arn, Subject=safe_subject, Message=message)

    try:
        await asyncio.to_thread(_do)
        log.info("notify.published", subject=safe_subject)
        return True
    except Exception as exc:  # noqa: BLE001 — 알림 실패가 본 흐름을 막지 않음
        log.warning("notify.publish_failed", error=str(exc))
        return False
