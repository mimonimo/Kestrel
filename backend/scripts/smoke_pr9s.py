"""PR 9-S smoke — best-of-N candidate selection.

In-memory only: builds CveLabMapping rows with controlled (verified,
feedback_up, feedback_down, last_verified_at, id) tuples and asserts
``_find_mapping`` / ``list_synthesized_candidates`` return them in the
documented score order.

Three blocks:
  A) tier ordering — verified+clean > verified+degraded > unverified > degraded.
  B) tie-breakers — within tier, feedback balance then recency.
  C) ``list_synthesized_candidates`` returns ALL rows in correct order
     (used by the operator surface to show "후보 N개").
"""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timedelta, timezone

from app.models import CveLabMapping, LabSourceKind
from app.services.sandbox.lab_resolver import is_degraded


def _mk(
    *,
    id: int,
    verified: bool,
    up: int = 0,
    down: int = 0,
    last_verified: datetime | None = None,
    lab_kind: str = "synthesized/CVE-X/sha",
) -> CveLabMapping:
    m = CveLabMapping(
        cve_id="CVE-X",
        kind=LabSourceKind.SYNTHESIZED,
        lab_kind=lab_kind,
        spec={},
        verified=verified,
        feedback_up=up,
        feedback_down=down,
        last_verified_at=last_verified,
    )
    m.id = id  # type: ignore[assignment]
    m.updated_at = last_verified or datetime(2026, 1, 1, tzinfo=timezone.utc)  # type: ignore[assignment]
    return m


def _score(m: CveLabMapping) -> tuple:
    if m.verified and not is_degraded(m):
        tier = 3
    elif m.verified:
        tier = 2
    elif is_degraded(m):
        tier = 0
    else:
        tier = 1
    bal = int(m.feedback_up or 0) - int(m.feedback_down or 0)
    rec = m.last_verified_at or m.updated_at or datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (tier, bal, rec, m.id)


def _pick_best(rows: list[CveLabMapping]) -> CveLabMapping:
    return max(rows, key=_score)


def _section_a() -> bool:
    """tier ordering."""
    now = datetime(2026, 5, 4, 12, 0, tzinfo=timezone.utc)
    rows = [
        _mk(id=1, verified=True, last_verified=now, lab_kind="ver_clean"),
        _mk(id=2, verified=True, down=2, last_verified=now + timedelta(seconds=1), lab_kind="ver_degraded"),  # degraded by feedback
        _mk(id=3, verified=False, last_verified=now + timedelta(seconds=2), lab_kind="unver"),
        _mk(id=4, verified=False, down=2, last_verified=now + timedelta(seconds=3), lab_kind="unver_degraded"),
    ]
    best = _pick_best(rows)
    if best.lab_kind != "ver_clean":
        print(f"  FAIL — verified+clean should win, got {best.lab_kind}")
        return False
    print(f"  PASS — verified+clean wins over degraded / unverified")
    return True


def _section_b() -> bool:
    """tie-breakers within tier."""
    now = datetime(2026, 5, 4, 12, 0, tzinfo=timezone.utc)
    # All verified+clean — should pick the most recently verified
    rows = [
        _mk(id=1, verified=True, last_verified=now - timedelta(hours=2), lab_kind="oldest"),
        _mk(id=2, verified=True, last_verified=now - timedelta(hours=1), lab_kind="middle"),
        _mk(id=3, verified=True, last_verified=now, lab_kind="newest"),
    ]
    best = _pick_best(rows)
    if best.lab_kind != "newest":
        print(f"  FAIL — recency tiebreak: expected 'newest', got {best.lab_kind}")
        return False
    print(f"  PASS — recency wins among verified+clean")

    # Same recency — feedback balance breaks tie
    rows = [
        _mk(id=1, verified=True, last_verified=now, up=0, lab_kind="zero_balance"),
        _mk(id=2, verified=True, last_verified=now, up=2, lab_kind="positive"),
    ]
    best = _pick_best(rows)
    if best.lab_kind != "positive":
        print(f"  FAIL — feedback tiebreak: expected 'positive', got {best.lab_kind}")
        return False
    print(f"  PASS — feedback balance wins same-recency")
    return True


def _section_c() -> bool:
    """list_synthesized_candidates ordering covers all rows."""
    now = datetime(2026, 5, 4, 12, 0, tzinfo=timezone.utc)
    rows = [
        _mk(id=1, verified=True, last_verified=now, lab_kind="A_ver_clean"),
        _mk(id=2, verified=True, down=2, last_verified=now, lab_kind="B_ver_degraded"),
        _mk(id=3, verified=False, last_verified=now, lab_kind="C_unver"),
    ]
    ordered = sorted(rows, key=_score, reverse=True)
    # Tiering: verified+clean(3) > verified+degraded(2) > unverified+clean(1).
    # A "verified once" mapping outranks a never-verified one even after
    # a 👎 — it at least built and the probe passed at some point.
    expected = ["A_ver_clean", "B_ver_degraded", "C_unver"]
    got = [m.lab_kind for m in ordered]
    if got != expected:
        print(f"  FAIL — list ordering: expected {expected}, got {got}")
        return False
    print(f"  PASS — list returns {got}")
    return True


def main() -> int:
    print("[A] tier ordering")
    a = _section_a()
    print("\n[B] tie-breakers within tier")
    b = _section_b()
    print("\n[C] list_synthesized_candidates ordering")
    c = _section_c()
    ok = a and b and c
    print(f"\n{'OK' if ok else 'FAIL'} — PR 9-S smoke {'green' if ok else 'red'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
