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
"""
from __future__ import annotations

from typing import Any

import meilisearch

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models import Vulnerability

log = get_logger(__name__)


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
    "exactness",
    "publishedAt:desc",
]

TYPO_TOLERANCE = {
    "enabled": True,
    "minWordSizeForTypos": {"oneTypo": 5, "twoTypos": 9},
    "disableOnAttributes": ["cveId"],
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
        ["severity", "osFamilies", "types", "publishedAt", "source"]
    )
    index.update_sortable_attributes(["publishedAt", "cvssScore"])
    index.update_searchable_attributes(["cveId", "title", "summary", "description"])
    index.update_ranking_rules(RANKING_RULES)
    index.update_stop_words(STOP_WORDS)
    index.update_typo_tolerance(TYPO_TOLERANCE)
    log.info("meili.index_ready", index=s.meili_index)


def to_document(v: Vulnerability) -> dict[str, Any]:
    return {
        "cveId": v.cve_id,
        "title": v.title,
        "summary": v.summary,
        "description": v.description,
        "severity": v.severity.value if v.severity else None,
        "cvssScore": float(v.cvss_score) if v.cvss_score is not None else None,
        "publishedAt": int(v.published_at.timestamp()) if v.published_at else None,
        "source": v.source.value,
        "sourceUrl": v.source_url,
        "types": [t.name for t in v.types],
        "osFamilies": sorted({p.os_family.value for p in v.affected_products if p.os_family}),
    }


def index_many(vulns: list[Vulnerability]) -> None:
    if not vulns:
        return
    client = _client()
    index = client.index(get_settings().meili_index)
    docs = [to_document(v) for v in vulns]
    task = index.add_documents(docs)
    log.info("meili.indexed", count=len(docs), task=task.task_uid)


def search(
    query: str,
    severity: list[str] | None = None,
    os_family: list[str] | None = None,
    types: list[str] | None = None,
    from_ts: int | None = None,
    to_ts: int | None = None,
    limit: int = 20,
    offset: int = 0,
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
    if from_ts is not None:
        filters.append(f"publishedAt >= {from_ts}")
    if to_ts is not None:
        filters.append(f"publishedAt <= {to_ts}")

    return index.search(
        query,
        {
            "limit": limit,
            "offset": offset,
            "filter": " AND ".join(filters) if filters else None,
            "sort": ["publishedAt:desc"],
        },
    )


def meili_healthy() -> bool:
    """Cheap ping for /health. Never raises."""
    try:
        client = _client()
        client.health()
        return True
    except Exception:
        return False
