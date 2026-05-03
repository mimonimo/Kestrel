"""Backfill the new vulnerabilities.domains column for all existing rows.

One-shot: streams in batches, computes domains via the same classifier
the ingestion path uses, writes back with a single UPDATE per batch.

Idempotent — re-running rewrites the same domains for unchanged rows.
"""
from __future__ import annotations

import asyncio
import logging
from collections import Counter

from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from app.core.database import SessionLocal
from app.models import Vulnerability
from app.services.domain_classifier import infer_domains_from_row

logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

BATCH = 500


async def main() -> None:
    total = 0
    updated = 0
    none_cnt = 0
    multi_cnt = 0
    domain_counts: Counter[str] = Counter()

    async with SessionLocal() as session:
        # Stream by primary key to avoid OFFSET cost over 49k rows
        last_id = None
        while True:
            stmt = (
                select(Vulnerability)
                .options(selectinload(Vulnerability.affected_products))
                .order_by(Vulnerability.id)
                .limit(BATCH)
            )
            if last_id is not None:
                stmt = stmt.where(Vulnerability.id > last_id)
            rows = (await session.execute(stmt)).scalars().all()
            if not rows:
                break

            for v in rows:
                products = [(p.vendor, p.product) for p in v.affected_products]
                domains = infer_domains_from_row(
                    v.title or "", v.description or "", products
                )
                if domains != list(v.domains or []):
                    await session.execute(
                        update(Vulnerability)
                        .where(Vulnerability.id == v.id)
                        .values(domains=domains)
                    )
                    updated += 1
                if not domains:
                    none_cnt += 1
                else:
                    if len(domains) >= 2:
                        multi_cnt += 1
                    for d in domains:
                        domain_counts[d] += 1
                last_id = v.id

            await session.commit()
            total += len(rows)
            print(f"  processed={total}  updated={updated}", flush=True)

    print(f"\nDone. total={total} updated={updated} uncategorized={none_cnt} multi-domain={multi_cnt}")
    print("Final distribution:")
    for d, c in domain_counts.most_common():
        print(f"  {d:>16}: {c}")


if __name__ == "__main__":
    asyncio.run(main())
