"""Backfill VulnerabilityType labels for existing rows after CWE_TO_TYPE
expanded (PR 10-G).

Reads each vuln's ``raw_data`` (NVD weaknesses → CWE-NNN strings),
maps via the *current* CWE_TO_TYPE, and ensures the matching type rows
+ vulnerability_type_map links exist. Idempotent — safe to re-run.

Why a script vs. a migration: migrations can't easily run Python code
that reads JSONB shape and inserts via the ORM. A one-shot script keeps
the logic in the same module the live ingest uses (CWE_TO_TYPE).

After running, also reindex Meili so the new types appear in /search
filters: ``python /app/reindex_meili.py``.
"""
from __future__ import annotations

import asyncio
import logging
import sys
from collections import Counter
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import selectinload

from app.core.database import SessionLocal
from app.models import Vulnerability, VulnerabilityType
from app.services.ingestion import CWE_TO_TYPE

logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

BATCH = 500


def _extract_cwes(raw_data: dict | None) -> list[str]:
    """Pull every CWE-NNN string out of an NVD-shaped raw_data dict.

    Real NVD payloads come in two nested shapes: top-level ``weaknesses``
    (older API/test fixtures) or ``cve.weaknesses`` (modern API). Both
    are handled. Returns deduped list with order preserved.
    """
    if not raw_data:
        return []
    nodes: list = []
    if isinstance(raw_data.get("weaknesses"), list):
        nodes.extend(raw_data["weaknesses"])
    cve = raw_data.get("cve") or {}
    if isinstance(cve.get("weaknesses"), list):
        nodes.extend(cve["weaknesses"])

    seen: set[str] = set()
    out: list[str] = []
    for n in nodes:
        descs = (n or {}).get("description") or []
        for d in descs:
            v = (d or {}).get("value")
            if not v:
                continue
            up = str(v).strip().upper()
            if up.startswith("CWE-") and up not in seen:
                seen.add(up)
                out.append(up)
    return out


async def _ensure_types(session, labels: Iterable[str]) -> dict[str, VulnerabilityType]:
    """Upsert VulnerabilityType rows for the given labels and return a
    name → row map. ON CONFLICT DO NOTHING + re-select keeps it cheap."""
    labels = sorted({l for l in labels if l})
    if not labels:
        return {}
    for lab in labels:
        await session.execute(
            pg_insert(VulnerabilityType)
            .values(name=lab)
            .on_conflict_do_nothing(index_elements=["name"])
        )
    rows = (
        await session.scalars(
            select(VulnerabilityType).where(VulnerabilityType.name.in_(labels))
        )
    ).all()
    return {r.name: r for r in rows}


async def main() -> int:
    print(f"CWE map covers {len(set(CWE_TO_TYPE.values()))} distinct labels across "
          f"{len(CWE_TO_TYPE)} CWE codes.")

    # Phase 1 — pre-create all type rows we might need so per-batch loops
    # can attach references without round-trips.
    async with SessionLocal() as session:
        type_rows = await _ensure_types(session, set(CWE_TO_TYPE.values()))
        await session.commit()
    print(f"VulnerabilityType rows: {len(type_rows)} ready.")

    total = 0
    label_added = Counter()
    rows_with_new_label = 0
    last_id = None

    while True:
        async with SessionLocal() as session:
            stmt = (
                select(Vulnerability)
                .options(selectinload(Vulnerability.types))
                .order_by(Vulnerability.id)
                .limit(BATCH)
            )
            if last_id is not None:
                stmt = stmt.where(Vulnerability.id > last_id)
            rows = (await session.execute(stmt)).scalars().unique().all()
            if not rows:
                break

            # Re-fetch type rows in this session so attaching them is
            # safe (avoids cross-session detached-instance errors).
            type_rows = await _ensure_types(session, set(CWE_TO_TYPE.values()))

            batch_changed = False
            for v in rows:
                cwes = _extract_cwes(v.raw_data)
                if not cwes:
                    last_id = v.id
                    continue
                wanted = {CWE_TO_TYPE[c] for c in cwes if c in CWE_TO_TYPE}
                if not wanted:
                    last_id = v.id
                    continue
                existing = {t.name for t in v.types}
                missing = wanted - existing
                if not missing:
                    last_id = v.id
                    continue
                rows_with_new_label += 1
                for label in missing:
                    row = type_rows.get(label)
                    if row is None:
                        continue
                    v.types.append(row)
                    label_added[label] += 1
                batch_changed = True
                last_id = v.id

            if batch_changed:
                await session.commit()
            else:
                # Still advance cursor — last_id was set in the loop.
                pass

            total += len(rows)
            print(f"  processed={total}  rows_with_new_label={rows_with_new_label}  "
                  f"labels_added={dict(label_added.most_common(8))}", flush=True)

    print(f"\nDone. total={total} rows_with_new_label={rows_with_new_label}")
    print("Per-label additions:")
    for label, c in label_added.most_common():
        print(f"  {label:>22}: +{c}")
    print("\n(re-run reindex_meili.py to surface the new types in Meili filters)")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
