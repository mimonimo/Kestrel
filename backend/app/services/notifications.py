"""자산 매칭 알림 — 새 CVE 가 사용자 자산에 매칭되면 인앱 + 웹훅으로 전달.

PR 10-FB. 수집 파이프라인(ingestion.run_parser)이 *증분* 실행에서 새로 들어온
CVE id 목록을 ``notify_new_cves`` 에 넘긴다(전체 백필은 호출 안 함 — 25만 건을
한꺼번에 알림하면 안 되니까).

흐름:
1. user_assets 전부 로드(작은 테이블) + 새 CVE 들의 affected_products(벤더·제품)
   + vuln 메타(severity·title) 로드.
2. Python 에서 ILIKE 동등 매칭(assets._to_ilike 의 ``*`` 와일드카드 규칙과 동일).
3. 매칭 건마다 Notification 행 생성(unique index 로 사용자×CVE×제품 중복 무시).
4. 새 알림이 생긴 사용자별로 enabled 채널(Slack/Discord 웹훅)에 best-effort POST.
"""
from __future__ import annotations

import re
import uuid
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import background_session
from app.core.logging import get_logger
from app.models import (
    AffectedProduct,
    Notification,
    NotificationChannel,
    UserAsset,
    Vulnerability,
)

log = get_logger(__name__)


def _pattern_to_regex(pattern: str) -> re.Pattern[str]:
    """assets._to_ilike 와 같은 의미의 매처 — ``*`` 만 와일드카드, 나머지는 리터럴,
    전체 문자열 앵커, 대소문자 무시. ``*`` 없으면 정확 일치."""
    rx = re.escape(pattern).replace(r"\*", ".*")
    return re.compile(f"^{rx}$", re.IGNORECASE)


def _public_base_url() -> str:
    """CVE 링크용 공개 베이스 URL. cors_origins 첫 항목에서 유도(운영은 nip.io)."""
    origins = get_settings().cors_origins
    if origins:
        return origins[0].rstrip("/")
    return ""


def _format_message(cve_id: str, severity: str | None, vendor: str | None,
                    product: str | None, title: str | None) -> str:
    base = _public_base_url()
    link = f"{base}/cve/{cve_id}" if base else cve_id
    sev = (severity or "UNRATED").upper()
    asset = f"{vendor or ''}/{product or ''}".strip("/")
    head = f"🔔 {cve_id} ({sev}) — 내 자산 {asset} 에 영향"
    body = (title or "").strip()
    return f"{head}\n{body}\n{link}".strip()


async def _dispatch_webhook(client: httpx.AsyncClient, kind: str, url: str, message: str) -> None:
    """Slack/Discord incoming webhook best-effort POST. 실패해도 수집은 안 막는다."""
    payload: dict[str, Any] = {"content": message} if kind == "discord" else {"text": message}
    try:
        resp = await client.post(url, json=payload, timeout=10.0)
        if resp.status_code >= 300:
            log.warning("notify.webhook_bad_status", kind=kind, status=resp.status_code)
    except Exception as e:  # noqa: BLE001 — 외부 웹훅 장애가 수집/알림을 막으면 안 됨
        log.warning("notify.webhook_failed", kind=kind, error=str(e))


async def notify_new_cves(cve_ids: list[str]) -> int:
    """새 CVE 목록을 자산과 매칭해 알림 생성/발송. 생성된 인앱 알림 수 반환."""
    if not cve_ids:
        return 0

    async with background_session() as session:
        assets = (await session.execute(select(UserAsset))).scalars().all()
        if not assets:
            return 0  # 등록된 자산이 없으면 알림 대상 없음

        # 새 CVE 들의 affected_products + vuln 메타.
        rows = (
            await session.execute(
                select(
                    Vulnerability.cve_id,
                    Vulnerability.severity,
                    Vulnerability.title,
                    AffectedProduct.vendor,
                    AffectedProduct.product,
                )
                .join(AffectedProduct, AffectedProduct.vulnerability_id == Vulnerability.id)
                .where(Vulnerability.cve_id.in_(cve_ids))
            )
        ).all()
        if not rows:
            return 0

        # 자산 패턴 컴파일(자산 수만큼 1회).
        compiled = [
            (a.user_id, a.vendor, a.product,
             _pattern_to_regex(a.vendor), _pattern_to_regex(a.product))
            for a in assets
        ]

        # 매칭 → (user_id, cve_id, vendor, product, severity, title) 후보.
        # 같은 (user, cve, product) 는 set 으로 1차 중복 제거.
        seen: set[tuple[uuid.UUID, str, str]] = set()
        to_insert: list[dict[str, Any]] = []
        users_hit: set[uuid.UUID] = set()
        for cve_id, severity, title, ap_vendor, ap_product in rows:
            v = ap_vendor or ""
            p = ap_product or ""
            for uid, a_vendor, a_product, rx_v, rx_p in compiled:
                if rx_v.match(v) and rx_p.match(p):
                    key = (uid, cve_id, a_product)
                    if key in seen:
                        continue
                    seen.add(key)
                    sev = severity.value if hasattr(severity, "value") else severity
                    to_insert.append({
                        "user_id": uid,
                        "cve_id": cve_id,
                        "vendor": a_vendor,
                        "product": a_product,
                        "severity": sev,
                        "title": (title or "")[:300] or None,
                    })
                    users_hit.add(uid)

        if not to_insert:
            return 0

        # unique index(user_id, cve_id, product) 로 기존 알림은 무시 → 재갱신 시 재알림 안 함.
        stmt = pg_insert(Notification).on_conflict_do_nothing(
            index_elements=["user_id", "cve_id", "product"]
        )
        result = await session.execute(stmt, to_insert)
        await session.commit()
        created = result.rowcount or 0

        # 새 알림이 실제로 생긴 사용자에게만 웹훅 발송.
        if created:
            await _fanout_webhooks(session, users_hit, to_insert)

        log.info("notify.done", candidates=len(to_insert), created=created, users=len(users_hit))
        return created


async def _fanout_webhooks(
    session: AsyncSession, user_ids: set[uuid.UUID], items: list[dict[str, Any]]
) -> None:
    channels = (
        await session.execute(
            select(NotificationChannel).where(
                NotificationChannel.user_id.in_(user_ids),
                NotificationChannel.enabled.is_(True),
            )
        )
    ).scalars().all()
    if not channels:
        return
    by_user: dict[uuid.UUID, list[NotificationChannel]] = {}
    for c in channels:
        by_user.setdefault(c.user_id, []).append(c)

    async with httpx.AsyncClient() as client:
        for it in items:
            chans = by_user.get(it["user_id"])
            if not chans:
                continue
            msg = _format_message(
                it["cve_id"], it["severity"], it["vendor"], it["product"], it["title"]
            )
            for ch in chans:
                await _dispatch_webhook(client, ch.kind, ch.url, msg)
