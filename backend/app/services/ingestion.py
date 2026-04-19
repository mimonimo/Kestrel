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
from app.services.parsers.base import BaseParser, ParsedVulnerability
from app.services.search_service import index_many
from app.services.summarizer import generate_summary

log = get_logger(__name__)

# CWE → human label mapping (non-exhaustive; extend as needed)
CWE_TO_TYPE = {
    "CWE-79": "XSS",
    "CWE-89": "SQLi",
    "CWE-352": "CSRF",
    "CWE-918": "SSRF",
    "CWE-22": "LFI",
    "CWE-611": "XXE",
    "CWE-77": "RCE",
    "CWE-78": "RCE",
    "CWE-94": "RCE",
    "CWE-287": "Auth",
    "CWE-863": "Auth",
    "CWE-400": "DoS",
    "CWE-770": "DoS",
}


async def run_parser(parser: BaseParser) -> dict:
    """Execute one parser end-to-end. Creates an IngestionLog row."""
    started = datetime.now(timezone.utc)
    counts = {"processed": 0, "new": 0, "updated": 0}
    error: str | None = None
    new_or_updated_ids: list[str] = []

    async with SessionLocal() as session:
        log_row = IngestionLog(source=parser.source, started_at=started, status="running")
        session.add(log_row)
        await session.flush()
        await session.commit()

        try:
            async for parsed in parser.fetch(since=await _last_success(session, parser.source)):
                result = await _upsert(session, parsed)
                counts["processed"] += 1
                if result == "new":
                    counts["new"] += 1
                    new_or_updated_ids.append(parsed.cve_id)
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

    # Index touched rows into Meilisearch (post-commit so they're visible)
    if new_or_updated_ids:
        async with SessionLocal() as session:
            rows = (
                (
                    await session.execute(
                        select(Vulnerability)
                        .where(Vulnerability.cve_id.in_(new_or_updated_ids))
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
            index_many(list(rows))

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
            types=type_rows,
            affected_products=products,
            references=refs,
        )
        session.add(vuln)
        return "new"

    # Existing row — relationships were eagerly loaded above, so iteration is safe.
    changed = False
    if parsed.modified_at and (not existing.modified_at or parsed.modified_at > existing.modified_at):
        existing.title = parsed.title
        existing.description = parsed.description
        existing.summary = summary
        existing.cvss_score = parsed.cvss_score
        existing.cvss_vector = parsed.cvss_vector
        existing.severity = parsed.severity
        existing.modified_at = parsed.modified_at
        existing.raw_data = parsed.raw_data
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
