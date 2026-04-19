"""NVD 2.0 API parser.

Docs: https://nvd.nist.gov/developers/vulnerabilities
Rate limit: 5 req / 30s (keyless) · 50 req / 30s (with API key).
We scope one sliding window per process via Redis so multiple workers share
the budget.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.redis_client import get_redis
from app.models import OsFamily, RefType, Severity, Source
from app.services.parsers.base import (
    BaseParser,
    ParsedProduct,
    ParsedReference,
    ParsedVulnerability,
)
from app.services.rate_limiter import RateLimiter
from app.utils.retry import TransientHttpError, retrying

log = get_logger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000


_SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


class NvdParser(BaseParser):
    source: ClassVar[Source] = Source.NVD
    name: ClassVar[str] = "NVD"

    def __init__(self, api_key_override: str | None = None) -> None:
        self.settings = get_settings()
        self.api_key_override = api_key_override

    async def fetch(self, since: datetime | None = None) -> AsyncIterator[ParsedVulnerability]:
        api_key = self.api_key_override or self.settings.nvd_api_key
        headers = {"apiKey": api_key} if api_key else {}

        max_req = 50 if api_key else 5
        redis = await get_redis()
        limiter = RateLimiter(redis, key="nvd", max_requests=max_req, window_seconds=30.0)

        params: dict[str, Any] = {"resultsPerPage": PAGE_SIZE, "startIndex": 0}
        now = datetime.now(timezone.utc)
        if since is not None:
            # Incremental: fetch anything touched since the last successful run.
            params["lastModStartDate"] = since.astimezone(timezone.utc).isoformat(timespec="seconds")
            params["lastModEndDate"] = now.isoformat(timespec="seconds")
        else:
            # First run: grab the last 30 days of CVEs (published window) so the
            # dashboard fills with recent data instead of crawling the 1990s back-catalog.
            window_start = now - timedelta(days=30)
            params["pubStartDate"] = window_start.isoformat(timespec="seconds")
            params["pubEndDate"] = now.isoformat(timespec="seconds")

        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            while True:
                await limiter.acquire()
                async for attempt in retrying():
                    with attempt:
                        resp = await client.get(NVD_API, params=params)
                        if resp.status_code >= 500 or resp.status_code == 429:
                            raise TransientHttpError(f"NVD {resp.status_code}")
                        resp.raise_for_status()
                        payload = resp.json()

                items = payload.get("vulnerabilities", [])
                log.info("nvd.page", fetched=len(items), start=params["startIndex"])
                for item in items:
                    yield self._normalize(item)

                total = payload.get("totalResults", 0)
                params["startIndex"] += PAGE_SIZE
                if params["startIndex"] >= total or not items:
                    return

    def _normalize(self, item: dict) -> ParsedVulnerability:
        cve = item["cve"]
        cve_id = cve["id"]
        title = _pick_description(cve.get("descriptions", []), limit=140) or cve_id
        description = _pick_description(cve.get("descriptions", [])) or ""

        cvss_score = None
        cvss_vector = None
        severity = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                data = entries[0].get("cvssData", {})
                cvss_score = data.get("baseScore")
                cvss_vector = data.get("vectorString")
                sev = (data.get("baseSeverity") or entries[0].get("baseSeverity") or "").upper()
                severity = _SEVERITY_MAP.get(sev)
                break

        types = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                cwe = desc.get("value")
                if cwe:
                    types.append(cwe)  # store raw CWE; orchestrator maps to labels

        products = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    cpe_uri = cpe.get("criteria", "")
                    vendor, product = _parse_cpe(cpe_uri)
                    products.append(
                        ParsedProduct(
                            vendor=vendor,
                            product=product,
                            os_family=_guess_os(cpe_uri),
                            version_range=_build_version_range(cpe),
                            cpe_string=cpe_uri,
                        )
                    )

        refs = [
            ParsedReference(url=r["url"], ref_type=_classify_ref(r))
            for r in cve.get("references", [])
            if r.get("url")
        ]

        return ParsedVulnerability(
            cve_id=cve_id,
            title=title,
            description=description,
            source=Source.NVD,
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            cvss_score=float(cvss_score) if cvss_score is not None else None,
            cvss_vector=cvss_vector,
            severity=severity,
            published_at=_parse_ts(cve.get("published")),
            modified_at=_parse_ts(cve.get("lastModified")),
            types=types,
            affected_products=products,
            references=refs,
            raw_data=item,
        )


def _pick_description(descs: list[dict], limit: int | None = None) -> str | None:
    for d in descs:
        if d.get("lang") == "en":
            text = d.get("value", "")
            return text[:limit] if limit else text
    return None


def _parse_ts(s: str | None) -> datetime | None:
    """Parse NVD ISO timestamps, forcing UTC when the source omits a zone.

    NVD sometimes returns naive strings (e.g. '2025-01-01T00:00:00.123') and
    sometimes trailing-Z strings. Either way we hand back a tz-aware datetime
    so downstream ``published < existing.modified_at`` comparisons don't crash
    with offset-naive/offset-aware mismatch errors."""
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_cpe(uri: str) -> tuple[str, str]:
    # cpe:2.3:a:vendor:product:version:...
    parts = uri.split(":")
    if len(parts) >= 5:
        return parts[3], parts[4]
    return "unknown", "unknown"


def _guess_os(cpe: str) -> OsFamily:
    lower = cpe.lower()
    if "microsoft" in lower or "windows" in lower:
        return OsFamily.WINDOWS
    if "apple" in lower and "ios" in lower:
        return OsFamily.IOS
    if "apple" in lower or "macos" in lower or "mac_os" in lower:
        return OsFamily.MACOS
    if "android" in lower:
        return OsFamily.ANDROID
    if "linux" in lower or "kernel" in lower or "redhat" in lower or "debian" in lower or "ubuntu" in lower:
        return OsFamily.LINUX
    return OsFamily.OTHER


def _build_version_range(cpe_match: dict) -> str | None:
    vs_start = cpe_match.get("versionStartIncluding") or cpe_match.get("versionStartExcluding")
    vs_end = cpe_match.get("versionEndIncluding") or cpe_match.get("versionEndExcluding")
    if vs_start and vs_end:
        return f"{vs_start} - {vs_end}"
    if vs_end:
        return f"< {vs_end}"
    if vs_start:
        return f">= {vs_start}"
    return None


def _classify_ref(ref: dict) -> RefType:
    tags = {t.lower() for t in ref.get("tags", [])}
    if "patch" in tags:
        return RefType.PATCH
    if "exploit" in tags:
        return RefType.EXPLOIT
    if "third party advisory" in tags or "vendor advisory" in tags:
        return RefType.ADVISORY
    return RefType.ADVISORY
