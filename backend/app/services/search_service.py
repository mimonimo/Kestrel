"""Meilisearch indexer + query service.

Keeps a single index "vulnerabilities" synced. Documents are stored in
camelCase to match the Next.js frontend types 1:1 — when we bypass the
Postgres hydration step in the future, the Meilisearch response is usable
as-is.

Step 5 tuning
-------------
- Custom ranking rules: typo / words / attribute / proximity / exactness.
  CVE IDs and titles are high-signal, so `attribute` is prioritised.
- Stop words: common English + security filler ("the", "a", "vulnerability",
  "allows", "attacker", "could", ...) to keep short queries sharp.
- typoTolerance.minWordSizeForTypos lifted so short tokens (e.g. "CVE",
  "XSS", "RCE") match exactly. CVE numbers are disabled from typo entirely.

PR-A (Step 10) sort/filter expansion
------------------------------------
- ``severityRank`` numeric facet so the dashboard's "심각도순" sort can be
  pushed to the engine instead of re-sorting the current page on the
  client (the previous behavior only sorted the 20 visible items, which
  the user reported as broken sort across pages).
- ``search()`` accepts ``sort`` + ``attributes_to_search_on`` so the API
  layer can issue a cveId-restricted retry for queries like "44228" that
  would otherwise compete with title/summary tokens for relevance.
"""
from __future__ import annotations

import re
from typing import Any

import meilisearch

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models import Vulnerability

log = get_logger(__name__)


# Meili 문서 식별자로 안전한(그리고 검색 대상으로 유효한) CVE id 패턴.
_VALID_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


STOP_WORDS = [
    "a", "an", "the", "of", "in", "on", "to", "for", "and", "or", "with",
    "is", "are", "was", "were", "be", "been",
    "vulnerability", "vulnerabilities", "issue", "allows", "allow",
    "attacker", "attackers", "could", "may", "might", "can",
]

RANKING_RULES = [
    "words",
    "typo",
    "attribute",
    "proximity",
    # ``sort`` 규칙이 있어야 쿼리 타임 sort 파라미터(publishedAt/severity/cvss
    # 정렬)를 쓸 수 있다. 빠지면 Meili 가 invalid_search_sort 로 모든 정렬 검색을
    # 거부 → 백엔드가 매번 느린 Postgres 폴백으로 떨어진다(취약점 조회 지연/실패).
    "sort",
    "exactness",
    "publishedAt:desc",
]

TYPO_TOLERANCE = {
    "enabled": True,
    "minWordSizeForTypos": {"oneTypo": 5, "twoTypos": 9},
    "disableOnAttributes": ["cveId"],
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Meili 페이지네이션 상한 — 기본 1000 이면 정렬 검색이 최신 1000건까지만
# 도달 가능(오래된 CVE 조회 불가). 코퍼스 규모(~36만)+성장 여유로 상향.
MEILI_MAX_TOTAL_HITS = 1_000_000

# Frontend SortKey → Meilisearch sort spec. When the user picks "심각도순",
# break ties by recency so two equally-severe CVEs aren't shuffled
# arbitrarily between page loads.
SORT_SPECS: dict[str, list[str]] = {
    "newest": ["publishedAt:desc"],
    "oldest": ["publishedAt:asc"],
    "severity": ["severityRank:desc", "publishedAt:desc"],
    "cvss": ["cvssScore:desc", "publishedAt:desc"],
}


def _client() -> meilisearch.Client:
    s = get_settings()
    return meilisearch.Client(s.meili_host, s.meili_master_key)


def ensure_index() -> None:
    """Create the index with filter/sort attrs. Idempotent."""
    s = get_settings()
    client = _client()
    try:
        client.create_index(s.meili_index, {"primaryKey": "cveId"})
    except meilisearch.errors.MeilisearchApiError as e:
        if "already exists" not in str(e):
            raise

    index = client.index(s.meili_index)
    index.update_filterable_attributes(
        ["severity", "osFamilies", "types", "publishedAt", "source", "domains"]
    )
    index.update_sortable_attributes(["publishedAt", "cvssScore", "severityRank"])
    index.update_searchable_attributes(["cveId", "title", "summary", "description"])
    index.update_ranking_rules(RANKING_RULES)
    index.update_stop_words(STOP_WORDS)
    index.update_typo_tolerance(TYPO_TOLERANCE)
    # Meili 기본 maxTotalHits=1000 → 정렬 검색이 최신 1000건까지만 페이지네이션
    # 가능하고 그 이상(오래된 CVE)은 빈 결과가 된다. 코퍼스(~36만)+성장분을
    # 모두 넘길 수 있게 상향. (offset 기반 deep page 는 사용자 주도라 허용)
    index.update_pagination_settings({"maxTotalHits": MEILI_MAX_TOTAL_HITS})
    log.info("meili.index_ready", index=s.meili_index)


def to_document(v: Vulnerability) -> dict[str, Any]:
    sev = v.severity.value if v.severity else None
    return {
        "cveId": v.cve_id,
        "title": v.title,
        "summary": v.summary,
        "description": v.description,
        "severity": sev,
        "severityRank": SEVERITY_RANK.get(sev, 0),
        "cvssScore": float(v.cvss_score) if v.cvss_score is not None else None,
        "publishedAt": int(v.published_at.timestamp()) if v.published_at else None,
        "source": v.source.value,
        "sources": list(v.sources or [v.source.value]),
        "sourceUrl": v.source_url,
        "types": [t.name for t in v.types],
        "osFamilies": sorted({p.os_family.value for p in v.affected_products if p.os_family}),
        "domains": list(v.domains or []),
    }


def index_many(vulns: list[Vulnerability]) -> None:
    if not vulns:
        return
    client = _client()
    index = client.index(get_settings().meili_index)
    # Meili 문서 식별자는 영숫자/하이픈/언더스코어만 허용 — cve_id 에 en-dash 나
    # 공백/콜론 같은 오염 문자가 있으면 *배치 전체*(500건) 색인이 실패한다.
    # 정규 CVE 형식이 아닌 문서는 건너뛰어, 한 건의 불량 id 가 배치를 오염시키지
    # 않게 한다(검색 색인 누락 방지).
    docs = []
    skipped = 0
    for v in vulns:
        if not _VALID_CVE_ID.match(v.cve_id or ""):
            skipped += 1
            continue
        docs.append(to_document(v))
    if skipped:
        log.warning("meili.skipped_invalid_cve_id", count=skipped)
    if not docs:
        return
    task = index.add_documents(docs)
    log.info("meili.indexed", count=len(docs), task=task.task_uid)


def search(
    query: str,
    severity: list[str] | None = None,
    os_family: list[str] | None = None,
    types: list[str] | None = None,
    domains: list[str] | None = None,
    from_ts: int | None = None,
    to_ts: int | None = None,
    limit: int = 20,
    offset: int = 0,
    sort: str = "newest",
    attributes_to_search_on: list[str] | None = None,
) -> dict:
    client = _client()
    index = client.index(get_settings().meili_index)

    filters: list[str] = []
    if severity:
        filters.append("severity IN [" + ", ".join(f'"{s}"' for s in severity) + "]")
    if os_family:
        filters.append("osFamilies IN [" + ", ".join(f'"{o}"' for o in os_family) + "]")
    if types:
        filters.append("types IN [" + ", ".join(f'"{t}"' for t in types) + "]")
    if domains:
        filters.append("domains IN [" + ", ".join(f'"{d}"' for d in domains) + "]")
    if from_ts is not None:
        filters.append(f"publishedAt >= {from_ts}")
    if to_ts is not None:
        filters.append(f"publishedAt <= {to_ts}")

    opts: dict[str, Any] = {
        "limit": limit,
        "offset": offset,
        "filter": " AND ".join(filters) if filters else None,
        "sort": SORT_SPECS.get(sort, SORT_SPECS["newest"]),
    }
    if attributes_to_search_on:
        opts["attributesToSearchOn"] = attributes_to_search_on
    return index.search(query, opts)


def meili_healthy() -> bool:
    """Cheap ping for /health. Never raises."""
    try:
        client = _client()
        client.health()
        return True
    except Exception:
        return False
