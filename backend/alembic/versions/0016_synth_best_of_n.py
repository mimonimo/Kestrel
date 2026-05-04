"""cve_lab_mappings: relax unique to (cve_id, kind, lab_kind) for best-of-N (PR 9-S)

Until now ``UniqueConstraint(cve_id, kind)`` made each CVE carry at most
one synthesized row — re-synthesis overwrote the prior attempt. With the
backend probe registry now covering 9 vuln classes (PR 9-L/M/N), the next
verification gain is *keeping multiple candidate specs per CVE* and letting
the resolver pick the best by score (verified > unverified, not-degraded >
degraded, recent > stale). This migration unblocks that by widening the
uniqueness key to also include ``lab_kind``:

  * vulhub: lab_kind is a fixed vulhub directory path per CVE → still
    one row per CVE.
  * generic: lab_kind is the catalog class name ("rce" / "ssti" / …) →
    still one row per CVE per class (was implicitly the same).
  * synthesized: lab_kind = "synthesized/<cve>/<spec_sha>" — sha is the
    content hash of the LLM's spec, so distinct synthesis attempts get
    distinct lab_kind values and now coexist as candidates.

Down-migration restores the old unique by collapsing duplicates: keep
the most recently verified row per (cve_id, kind) and delete the rest.
This is destructive — only do it on a snapshot you're willing to lose.

Revision ID: 0016
Revises: 0015
Create Date: 2026-05-04
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: Union[str, None] = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(
        "uq_cve_lab_mappings_cve_kind", "cve_lab_mappings", type_="unique"
    )
    op.create_unique_constraint(
        "uq_cve_lab_mappings_cve_kind_labkind",
        "cve_lab_mappings",
        ["cve_id", "kind", "lab_kind"],
    )


def downgrade() -> None:
    # Collapse extra synthesized candidates so the narrower unique can be
    # re-applied. Keep the row with the most recent last_verified_at
    # (NULLs last); ties broken by id desc.
    op.execute(
        """
        DELETE FROM cve_lab_mappings a
         USING cve_lab_mappings b
         WHERE a.cve_id = b.cve_id
           AND a.kind = b.kind
           AND a.id <> b.id
           AND (
                COALESCE(a.last_verified_at, '-infinity') < COALESCE(b.last_verified_at, '-infinity')
                OR (
                  COALESCE(a.last_verified_at, '-infinity') = COALESCE(b.last_verified_at, '-infinity')
                  AND a.id < b.id
                )
           )
        """
    )
    op.drop_constraint(
        "uq_cve_lab_mappings_cve_kind_labkind",
        "cve_lab_mappings",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_cve_lab_mappings_cve_kind",
        "cve_lab_mappings",
        ["cve_id", "kind"],
    )
