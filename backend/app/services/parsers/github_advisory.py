"""GitHub Security Advisory (GHSA) parser via GraphQL API.

Doc: https://docs.github.com/en/graphql/reference/objects#securityadvisory
Rate limit: 5000 points/hour for authenticated calls; each GHSA list query
consumes ~1 point.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any, ClassVar

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.redis_client import get_redis
from app.models import RefType, Severity, Source
from app.services.parsers.base import (
    BaseParser,
    ParsedReference,
    ParsedVulnerability,
)
from app.services.rate_limiter import RateLimiter
from app.utils.retry import TransientHttpError, retrying

log = get_logger(__name__)

GH_GRAPHQL = "https://api.github.com/graphql"

QUERY = """
query($cursor: String, $since: DateTime) {
  securityAdvisories(first: 50, after: $cursor, orderBy: {field: PUBLISHED_AT, direction: DESC}, publishedSince: $since) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      permalink
      cvss { score vectorString }
      identifiers { type value }
      references { url }
    }
  }
}
"""

_SEV_MAP = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


class GithubAdvisoryParser(BaseParser):
    source: ClassVar[Source] = Source.GITHUB_ADVISORY
    name: ClassVar[str] = "GitHub Advisory"

    def __init__(self, token_override: str | None = None) -> None:
        self.settings = get_settings()
        self.token_override = token_override

    async def fetch(self, since: datetime | None = None) -> AsyncIterator[ParsedVulnerability]:
        token = self.token_override or self.settings.github_token
        if not token:
            # 토큰이 없으면 *실패* 로 처리. 과거엔 조용히 return(=success 0건)했는데,
            # 그러면 run_parser 가 finished_at 으로 since-baseline 을 당겨 토큰을
            # 나중에 등록해도 그 사이 advisory 를 영영 못 받는 since-window 갭이
            # 생겼다. 실패로 남기면 _last_success 가 무시 → 토큰 등록 후 첫 실행이
            # 자동으로 전체(since=None) 백필이 된다.
            raise RuntimeError(
                "GitHub 토큰이 없어 GHSA 를 가져올 수 없습니다 — 설정 > 외부 연결 키에서 등록하세요."
            )

        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        redis = await get_redis()
        limiter = RateLimiter(redis, key="github_graphql", max_requests=30, window_seconds=60.0)

        cursor: str | None = None
        since_iso = since.isoformat() if since else None

        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            while True:
                await limiter.acquire()
                variables: dict[str, Any] = {"cursor": cursor, "since": since_iso}

                async for attempt in retrying():
                    with attempt:
                        resp = await client.post(
                            GH_GRAPHQL, json={"query": QUERY, "variables": variables}
                        )
                        if resp.status_code == 429 or resp.status_code >= 500:
                            raise TransientHttpError(f"GitHub {resp.status_code}")
                        resp.raise_for_status()
                        payload = resp.json()

                if "errors" in payload:
                    # Surface the error to the ingestion_logs row instead
                    # of returning silently as "success: 0 items". Common
                    # causes: token revoked / scopes wrong / rate limited
                    # (5000 pts/hour for auth'd, 60 unauth'd) / GHSA API
                    # schema shift. The user-facing status panel then has
                    # something actionable.
                    summary = ", ".join(
                        e.get("message") or str(e) for e in payload["errors"][:3]
                    )
                    log.error("github.graphql_errors", errors=payload["errors"])
                    raise RuntimeError(
                        f"GHSA GraphQL 오류: {summary[:400]}"
                    )

                data = payload["data"]["securityAdvisories"]
                for node in data["nodes"]:
                    parsed = self._normalize(node)
                    if parsed:
                        yield parsed

                if not data["pageInfo"]["hasNextPage"]:
                    return
                cursor = data["pageInfo"]["endCursor"]

    def _normalize(self, node: dict) -> ParsedVulnerability | None:
        cve_id = None
        for ident in node.get("identifiers", []):
            if ident.get("type") == "CVE":
                cve_id = ident.get("value")
                break
        if not cve_id:
            return None  # skip non-CVE advisories

        cvss = node.get("cvss") or {}
        refs = [
            ParsedReference(url=r["url"], ref_type=RefType.ADVISORY)
            for r in node.get("references", [])
            if r.get("url")
        ]
        severity = _SEV_MAP.get((node.get("severity") or "").upper())
        summary = node.get("summary") or ""

        return ParsedVulnerability(
            cve_id=cve_id,
            title=summary[:180] if summary else cve_id,
            description=node.get("description") or summary,
            summary=summary[:300],
            source=Source.GITHUB_ADVISORY,
            source_url=node.get("permalink") or f"https://github.com/advisories/{node.get('ghsaId')}",
            cvss_score=cvss.get("score") or None,
            cvss_vector=cvss.get("vectorString"),
            severity=severity,
            published_at=_parse_ts(node.get("publishedAt")),
            modified_at=_parse_ts(node.get("updatedAt")),
            references=refs,
            raw_data=node,
        )


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
