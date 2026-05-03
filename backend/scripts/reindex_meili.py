"""Re-emit all vulnerability docs into Meilisearch.

Used after a search_service.to_document() change (added a new field) or
a settings change (filterable/sortable attrs). Idempotent — re-running
overwrites existing docs by primary key (cveId).
"""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.database import SessionLocal
from app.models import Vulnerability
from app.services.search_service import ensure_index, index_many

logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

BATCH = 500


async def main() -> None:
    ensure_index()
    total = 0
    last_id = None
    async with SessionLocal() as session:
        while True:
            stmt = (
                select(Vulnerability)
                .options(
                    selectinload(Vulnerability.types),
                    selectinload(Vulnerability.affected_products),
                    selectinload(Vulnerability.references),
                )
                .order_by(Vulnerability.id)
                .limit(BATCH)
            )
            if last_id is not None:
                stmt = stmt.where(Vulnerability.id > last_id)
            rows = (await session.execute(stmt)).scalars().unique().all()
            if not rows:
                break
            index_many(list(rows))
            total += len(rows)
            last_id = rows[-1].id
            print(f"  indexed={total}", flush=True)

    print(f"\nDone. {total} docs queued to Meili.")


if __name__ == "__main__":
    asyncio.run(main())
