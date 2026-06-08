"""참고 자료(reference) 링크의 페이지 메타(제목·요약)를 가져온다.

CVE 상세에서 "사이트로 나가지 않고도" 각 레퍼런스가 무슨 내용인지 보이도록
title / description(og 우선)을 추출한다. 결과는 URL 단위로 Redis 캐시(7일).

보안(중요): 외부 URL 을 서버에서 가져오므로 SSRF 를 막는다.
  - http/https 만 허용.
  - 호스트를 실제 resolve 해 사설·루프백·링크로컬·예약 대역이면 거부
    (169.254.169.254 등 클라우드 메타데이터·내부망 차단).
  - 타임아웃 6s, 본문 최대 512KB 만 읽음, HTML 만 파싱.
"""
from __future__ import annotations

import asyncio
import html as _html
import ipaddress
import json
import re
import socket
from urllib.parse import urljoin, urlparse

import httpx

from app.core.logging import get_logger
from app.core.redis_client import get_redis

log = get_logger(__name__)

_CACHE_TTL = 7 * 86400
_TIMEOUT = httpx.Timeout(6.0, connect=4.0)
_MAX_BYTES = 512 * 1024
_UA = "KestrelBot/1.0 (+https://www.kestrel.forum; vuln-intel reference preview)"
_MAX_REFS = 12


async def _resolve_safe(host: str | None) -> bool:
    if not host or host.lower() == "localhost":
        return False
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.run_in_executor(None, socket.getaddrinfo, host, None)
    except Exception:  # noqa: BLE001
        return False
    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        ):
            return False
    return True


# 봇/방화벽 차단·인터스티셜 페이지의 제목 — 실제 콘텐츠 제목이 아니므로 버린다
# (예: packetstormsecurity 의 "Bot Request Blocked", Cloudflare "Just a moment…").
_BLOCK_TITLE_RE = re.compile(
    r"(bot request blocked|just a moment|attention required|access denied|"
    r"request blocked|are you (?:a )?human|verify(?:ing)? you are human|"
    r"captcha|forbidden|access to this page has been denied|"
    r"please enable (?:cookies|javascript)|rate limit|too many requests|"
    r"service unavailable|not acceptable|page not found|404)",
    re.IGNORECASE,
)


def _find(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
    return m.group(1) if m else None


def _clean(s: str | None, limit: int) -> str | None:
    if not s:
        return None
    out = _html.unescape(re.sub(r"\s+", " ", s)).strip()
    return out[:limit] or None


def _extract(html_text: str, base_url: str) -> dict:
    head = html_text[:200_000]  # 메타는 head 에 있으므로 앞부분만
    title = (
        _find(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']', head)
        or _find(r'<title[^>]*>(.*?)</title>', head)
    )
    desc = (
        _find(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']', head)
        or _find(r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)["\']', head)
    )
    site = _find(r'<meta[^>]+property=["\']og:site_name["\'][^>]+content=["\']([^"\']+)["\']', head)
    image = (
        _find(r'<meta[^>]+property=["\']og:image(?::secure_url)?["\'][^>]+content=["\']([^"\']+)["\']', head)
        or _find(r'<meta[^>]+name=["\']twitter:image["\'][^>]+content=["\']([^"\']+)["\']', head)
    )

    clean_title = _clean(title, 200)
    # 봇 차단/인터스티셜 제목은 콘텐츠가 아니므로 버린다(프론트는 URL 만 노출).
    if clean_title and _BLOCK_TITLE_RE.search(clean_title):
        clean_title = None

    clean_image = _clean(image, 500)
    if clean_image:
        # 상대 경로 og:image 를 최종 URL 기준 절대 경로로. http(s) 만 노출.
        clean_image = urljoin(base_url, clean_image)
        if not clean_image.startswith(("http://", "https://")):
            clean_image = None

    return {
        "title": clean_title,
        "description": _clean(desc, 320),
        "siteName": _clean(site, 60),
        "image": clean_image,
    }


async def fetch_preview(url: str) -> dict:
    base = {
        "url": url,
        "title": None,
        "description": None,
        "siteName": None,
        "image": None,
        "ok": False,
    }
    redis = None
    key = f"kestrel:refprev:{url}"
    try:
        redis = await get_redis()
        cached = await redis.get(key)
        if cached:
            return json.loads(cached)
    except Exception:  # noqa: BLE001
        pass

    p = urlparse(url)
    if p.scheme in ("http", "https") and await _resolve_safe(p.hostname):
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT, follow_redirects=True, headers={"User-Agent": _UA}
            ) as client:
                async with client.stream("GET", url) as resp:
                    ctype = resp.headers.get("content-type", "")
                    if resp.status_code < 400 and ("html" in ctype or "text/" in ctype):
                        buf = b""
                        async for chunk in resp.aiter_bytes():
                            buf += chunk
                            if len(buf) >= _MAX_BYTES:
                                break
                        text = buf.decode(resp.encoding or "utf-8", errors="replace")
                        base.update(_extract(text, str(resp.url) or url))
                        base["ok"] = True
                    else:
                        # 비-HTML(PDF 등) 또는 오류 — 호스트만 사이트명으로.
                        base["siteName"] = p.hostname
        except Exception as exc:  # noqa: BLE001
            log.debug("refprev_fetch_failed", url=url, error=str(exc))

    if redis is not None:
        try:
            await redis.set(key, json.dumps(base), ex=_CACHE_TTL)
        except Exception:  # noqa: BLE001
            pass
    return base


async def previews_for(urls: list[str]) -> list[dict]:
    seen: list[str] = []
    for u in urls:
        if u and u not in seen:
            seen.append(u)
        if len(seen) >= _MAX_REFS:
            break
    sem = asyncio.Semaphore(6)

    async def _one(u: str) -> dict:
        async with sem:
            return await fetch_preview(u)

    return list(await asyncio.gather(*[_one(u) for u in seen]))
