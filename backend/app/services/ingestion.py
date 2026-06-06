"""Ingestion orchestrator: run a parser, upsert rows, record logs, index to Meili."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import SessionLocal
from app.core.logging import get_logger
from app.models import (
    AffectedProduct,
    IngestionLog,
    Source,
    Vulnerability,
    VulnerabilityReference,
    VulnerabilityType,
)
from app.services.domain_classifier import infer_domains
from app.services.parsers.base import BaseParser, ParsedVulnerability
from app.services.search_service import index_many
from app.services.summarizer import generate_summary

log = get_logger(__name__)

# CWE → human label mapping. Drives both ingestion-time labelling (new
# CVEs get type rows attached on insert) and the periodic backfill that
# stamps the same labels onto pre-existing rows. Keep aligned with the
# frontend filter chip set (lib/types.ts VulnType) so every chip has a
# real CWE source feeding it.
CWE_TO_TYPE = {
    # Reflected/stored XSS family
    "CWE-79": "XSS",
    "CWE-80": "XSS",
    "CWE-83": "XSS",
    "CWE-87": "XSS",
    # SQL injection
    "CWE-89": "SQLi",
    "CWE-564": "SQLi",
    # CSRF
    "CWE-352": "CSRF",
    # SSRF
    "CWE-918": "SSRF",
    # Path traversal vs. PHP-include LFI — kept as separate labels so
    # users can tell "any file read" from "PHP file include".
    "CWE-22": "Path-Traversal",
    "CWE-23": "Path-Traversal",
    "CWE-36": "Path-Traversal",
    "CWE-73": "Path-Traversal",
    "CWE-98": "LFI",
    # XXE / external entity
    "CWE-611": "XXE",
    "CWE-776": "XXE",
    "CWE-827": "XXE",
    # Command/code injection → RCE
    "CWE-77": "RCE",
    "CWE-78": "RCE",
    "CWE-94": "RCE",
    "CWE-95": "RCE",
    "CWE-1336": "RCE",  # SSTI 도 결국 코드 평가 — 사용자 시야에서 RCE
    # Insecure deserialization
    "CWE-502": "Deserialization",
    "CWE-915": "Deserialization",
    # Open redirect
    "CWE-601": "Open-Redirect",
    # Privilege escalation
    "CWE-269": "Privilege-Escalation",
    "CWE-264": "Privilege-Escalation",
    "CWE-250": "Privilege-Escalation",
    "CWE-272": "Privilege-Escalation",
    # Information disclosure
    "CWE-200": "Info-Disclosure",
    "CWE-201": "Info-Disclosure",
    "CWE-203": "Info-Disclosure",
    "CWE-209": "Info-Disclosure",
    "CWE-532": "Info-Disclosure",
    # Memory corruption (binary-side classes)
    "CWE-119": "Memory-Corruption",
    "CWE-120": "Memory-Corruption",
    "CWE-121": "Memory-Corruption",
    "CWE-122": "Memory-Corruption",
    "CWE-125": "Memory-Corruption",
    "CWE-415": "Memory-Corruption",
    "CWE-416": "Memory-Corruption",
    "CWE-787": "Memory-Corruption",
    "CWE-824": "Memory-Corruption",
    # Authentication / authorization broadly. PR 9-W lab classifier uses
    # a finer "auth-bypass" axis; user-facing chip stays as the broader
    # "Auth" label so it doesn't fragment.
    "CWE-287": "Auth",
    "CWE-306": "Auth",
    "CWE-425": "Auth",
    "CWE-639": "Auth",
    "CWE-862": "Auth",
    "CWE-863": "Auth",
    # Denial of service / resource exhaustion
    "CWE-400": "DoS",
    "CWE-770": "DoS",
    "CWE-835": "DoS",
}


async def run_parser(parser: BaseParser, full_resync: bool = False) -> dict:
    """Execute one parser end-to-end. Creates an IngestionLog row.

    ``full_resync=True`` ignores ``_last_success`` and re-pulls from the
    source's natural beginning — used to recover when a transient token
    failure left ``finished_at`` advanced past advisories that were
    never actually fetched (the since-window gap).
    """
    started = datetime.now(timezone.utc)
    counts = {"processed": 0, "new": 0, "updated": 0}
    error: str | None = None
    new_or_updated_ids: list[str] = []
    # 알림은 *신규* CVE 만(갱신 재알림 방지). 전체 백필(full_resync)에서는
    # 25만 건을 한꺼번에 알림하면 안 되므로 아예 수집하지 않는다.
    new_ids: list[str] = []

    async with SessionLocal() as session:
        log_row = IngestionLog(source=parser.source, started_at=started, status="running")
        session.add(log_row)
        await session.flush()
        await session.commit()

        try:
            since = (
                None if full_resync else await _last_success(session, parser.source)
            )
            async for parsed in parser.fetch(since=since):
                result = await _upsert(session, parsed)
                counts["processed"] += 1
                if result == "new":
                    counts["new"] += 1
                    new_or_updated_ids.append(parsed.cve_id)
                    if not full_resync:
                        new_ids.append(parsed.cve_id)
                elif result == "updated":
                    counts["updated"] += 1
                    new_or_updated_ids.append(parsed.cve_id)

                # Commit in batches to limit transaction size
                if counts["processed"] % 200 == 0:
                    await session.commit()
            await session.commit()
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
            log.exception("ingestion.failed", source=parser.source.value)
        finally:
            log_row.finished_at = datetime.now(timezone.utc)
            log_row.items_processed = counts["processed"]
            log_row.items_new = counts["new"]
            log_row.items_updated = counts["updated"]
            log_row.status = "failed" if error else "success"
            log_row.error_message = error
            await session.merge(log_row)
            await session.commit()

    # Index touched rows into Meilisearch (post-commit so they're visible).
    # *반드시 청크 단위로* — 전체 백필(NVD ~25만)에서 new_or_updated_ids 를 한
    # 쿼리의 ``cve_id.in_(...)`` 에 통째로 넣으면 asyncpg 의 단일 쿼리 파라미터
    # 한도(32767)를 넘겨 InterfaceError 로 색인 단계가 통째로 죽는다(Postgres 적재는
    # 이미 커밋됐지만 Meili 색인만 누락). 1000개씩 끊어 IN 절·메모리·Meili payload
    # 를 모두 안전하게 유지한다.
    CHUNK = 1000
    for i in range(0, len(new_or_updated_ids), CHUNK):
        chunk_ids = new_or_updated_ids[i : i + CHUNK]
        async with SessionLocal() as session:
            rows = (
                (
                    await session.execute(
                        select(Vulnerability)
                        .where(Vulnerability.cve_id.in_(chunk_ids))
                        .options(
                            selectinload(Vulnerability.types),
                            selectinload(Vulnerability.affected_products),
                            selectinload(Vulnerability.references),
                        )
                    )
                )
                .scalars()
                .unique()
                .all()
            )
            if rows:
                index_many(list(rows))

    # 자산 매칭 알림 — 증분 실행의 신규 CVE 만(full_resync 면 new_ids 는 비어 있음).
    # best-effort: 알림 실패가 수집 결과(success)를 뒤집지 않도록 try 로 감싼다.
    if new_ids:
        try:
            from app.services.notifications import notify_new_cves

            await notify_new_cves(new_ids)
        except Exception:
            log.exception("ingestion.notify_failed", source=parser.source.value)

    log.info("ingestion.done", source=parser.source.value, **counts, error=error)
    return {"source": parser.source.value, **counts, "error": error}


async def _last_success(session: AsyncSession, source: Source) -> datetime | None:
    stmt = (
        select(IngestionLog.finished_at)
        .where(IngestionLog.source == source, IngestionLog.status == "success")
        .order_by(IngestionLog.finished_at.desc())
        .limit(1)
    )
    return await session.scalar(stmt)


async def _upsert(session: AsyncSession, parsed: ParsedVulnerability) -> str:
    """Insert or update one vulnerability row. Returns 'new' | 'updated' | 'noop'.

    New rows: we resolve VulnerabilityType rows *before* constructing the parent
    and attach products/references via the constructor. That way nothing after
    flush has to touch an unloaded relationship collection (which would trigger
    an implicit lazy load and raise MissingGreenlet in async mode)."""
    existing = await session.scalar(
        select(Vulnerability)
        .where(Vulnerability.cve_id == parsed.cve_id)
        .options(
            selectinload(Vulnerability.types),
            selectinload(Vulnerability.affected_products),
            selectinload(Vulnerability.references),
        )
    )

    summary = parsed.summary or generate_summary(parsed.title, parsed.description)
    domains = infer_domains(parsed)

    if existing is None:
        type_rows = await _resolve_types(session, parsed.types)
        products = [
            AffectedProduct(
                vendor=p.vendor,
                product=p.product,
                os_family=p.os_family,
                version_range=p.version_range,
                cpe_string=p.cpe_string,
            )
            for p in parsed.affected_products
        ]
        refs = [
            VulnerabilityReference(url=r.url, ref_type=r.ref_type)
            for r in parsed.references
        ]
        vuln = Vulnerability(
            cve_id=parsed.cve_id,
            title=parsed.title,
            description=parsed.description,
            summary=summary,
            cvss_score=parsed.cvss_score,
            cvss_vector=parsed.cvss_vector,
            severity=parsed.severity,
            published_at=parsed.published_at,
            modified_at=parsed.modified_at,
            source=parsed.source,
            source_url=parsed.source_url,
            raw_data=parsed.raw_data,
            domains=domains,
            # PR 10-AF: track every contributing feed in the multi-source
            # array. Mirrors the singular ``source`` for new rows; existing
            # rows append below.
            sources=[parsed.source.value],
            types=type_rows,
            affected_products=products,
            references=refs,
        )
        session.add(vuln)
        return "new"

    # Existing row — relationships were eagerly loaded above, so iteration is safe.
    changed = False
    # PR 10-AF: always record this feed's contribution, even when the
    # parsed row is older than what we already have. Tracks "MITRE has
    # this CVE too" without overwriting NVD's enriched fields.
    if parsed.source.value not in (existing.sources or []):
        existing.sources = list(existing.sources or []) + [parsed.source.value]
        changed = True
    if parsed.modified_at and (not existing.modified_at or parsed.modified_at > existing.modified_at):
        existing.title = parsed.title
        existing.description = parsed.description
        existing.summary = summary
        existing.cvss_score = parsed.cvss_score
        existing.cvss_vector = parsed.cvss_vector
        existing.severity = parsed.severity
        existing.modified_at = parsed.modified_at
        existing.raw_data = parsed.raw_data
        existing.domains = domains
        await _replace_products(session, existing, parsed.affected_products)
        await _merge_references(session, existing, parsed.references, replace=True)
        await _merge_types(session, existing, parsed.types)
        changed = True
    elif parsed.source == Source.EXPLOIT_DB:
        # Exploit-DB contributes references even to existing CVEs
        await _merge_references(session, existing, parsed.references, replace=False)
        changed = True

    return "updated" if changed else "noop"


async def _resolve_types(session: AsyncSession, cwes: list[str]) -> list[VulnerabilityType]:
    """Upsert VulnerabilityType rows for the given CWE list and return them."""
    labels = {CWE_TO_TYPE.get(c) for c in cwes if c}
    labels.discard(None)
    if not labels:
        return []

    for label in labels:
        await session.execute(
            pg_insert(VulnerabilityType)
            .values(name=label)
            .on_conflict_do_nothing(index_elements=["name"])
        )

    rows = (
        (
            await session.execute(
                select(VulnerabilityType).where(VulnerabilityType.name.in_(labels))
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def _merge_types(
    session: AsyncSession, vuln: Vulnerability, cwes: list[str]
) -> None:
    """Attach any missing type labels to an already-loaded vulnerability."""
    rows = await _resolve_types(session, cwes)
    if not rows:
        return
    existing_labels = {t.name for t in vuln.types}
    for row in rows:
        if row.name not in existing_labels:
            vuln.types.append(row)


async def _replace_products(
    session: AsyncSession,
    vuln: Vulnerability,
    products,
) -> None:
    for ap in list(vuln.affected_products):
        await session.delete(ap)
    for p in products:
        vuln.affected_products.append(
            AffectedProduct(
                vendor=p.vendor,
                product=p.product,
                os_family=p.os_family,
                version_range=p.version_range,
                cpe_string=p.cpe_string,
            )
        )


async def _merge_references(
    session: AsyncSession,
    vuln: Vulnerability,
    refs,
    replace: bool = False,
) -> None:
    if replace:
        for r in list(vuln.references):
            await session.delete(r)

    existing_urls = {r.url for r in vuln.references}
    for ref in refs:
        if ref.url in existing_urls:
            continue
        vuln.references.append(VulnerabilityReference(url=ref.url, ref_type=ref.ref_type))
