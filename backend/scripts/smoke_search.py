"""PR-A smoke — search endpoint changes.

Three sections:

  A) ``_cve_id_ilike_pattern`` — accepts the digit/dash shapes we care
     about and rejects anything that isn't CVE-id-like.
  B) ``_pg_order_by`` — emits the right column ordering for each sort
     key (newest/oldest/severity/cvss).
  C) ``search_service.SORT_SPECS`` — every frontend SortKey maps to a
     Meilisearch sort spec (no silent fallback to "newest").

Pure python — no DB, no Meilisearch. Exit code 0 = green.
"""
from __future__ import annotations

import sys

from app.api.v1.search import _cve_id_ilike_pattern, _pg_order_by
from app.services import search_service


def _section_a() -> bool:
    cases: list[tuple[str, str | None]] = [
        ("44228", "%CVE-%44228%"),
        ("2021-44228", "%CVE-%2021-44228%"),
        ("CVE-2021", "%CVE-%2021%"),
        ("cve-2024-3", "%CVE-%2024-3%"),
        ("CVE2024", "%CVE-%2024%"),
        ("2021-44", "%CVE-%2021-44%"),
        ("  44228  ", "%CVE-%44228%"),
        # Not CVE-id-shaped — must return None so generic queries don't
        # gain an unintended ILIKE match.
        ("log4j", None),
        ("apache struts", None),
        ("12", None),  # too short (<3 chars after strip)
        ("", None),
        ("CVE-", None),
        ("100% off", None),
    ]
    ok = True
    for q, expected in cases:
        got = _cve_id_ilike_pattern(q)
        if got != expected:
            print(f"  FAIL — {q!r}: expected {expected!r}, got {got!r}")
            ok = False
        else:
            print(f"  PASS — {q!r} → {got!r}")
    return ok


def _section_b() -> bool:
    # We compare the rendered SQL fragment for each sort key. Don't pin
    # the exact string (SQLAlchemy formatting can drift across versions);
    # check that the right column appears in the first ORDER BY clause.
    keys = ["newest", "oldest", "severity", "cvss"]
    expectations = {
        "newest": "published_at desc",
        "oldest": "published_at asc",
        "severity": "case",  # CASE expression for severity ordinal
        "cvss": "cvss_score desc",
    }
    ok = True
    for key in keys:
        clauses = _pg_order_by(key)  # type: ignore[arg-type]
        if not clauses:
            print(f"  FAIL — {key!r}: no order_by clauses")
            ok = False
            continue
        rendered = str(clauses[0]).lower()
        if expectations[key] not in rendered:
            print(f"  FAIL — {key!r}: first clause {rendered!r} did not contain {expectations[key]!r}")
            ok = False
        else:
            print(f"  PASS — {key!r} → {rendered[:80]}…")
    return ok


def _section_c() -> bool:
    expected_keys = {"newest", "oldest", "severity", "cvss"}
    actual = set(search_service.SORT_SPECS.keys())
    if actual != expected_keys:
        print(f"  FAIL — SORT_SPECS keys {actual} != {expected_keys}")
        return False
    ok = True
    for key, spec in search_service.SORT_SPECS.items():
        if not spec or not isinstance(spec, list):
            print(f"  FAIL — {key!r}: empty/non-list spec {spec!r}")
            ok = False
            continue
        if not all(":" in s for s in spec):
            print(f"  FAIL — {key!r}: spec {spec!r} missing direction suffix")
            ok = False
            continue
        print(f"  PASS — {key!r} → {spec}")
    # severityRank must be in the meili sortable attribute set; we can't
    # ping meili here, but we can at least assert the spec references it.
    if not any("severityRank" in s for s in search_service.SORT_SPECS["severity"]):
        print("  FAIL — severity sort spec doesn't reference severityRank")
        ok = False
    return ok


def main() -> int:
    print("[A] _cve_id_ilike_pattern")
    a = _section_a()
    print("[B] _pg_order_by")
    b = _section_b()
    print("[C] search_service.SORT_SPECS")
    c = _section_c()
    if a and b and c:
        print("OK — PR-A smoke green")
        return 0
    print("FAIL — at least one PR-A smoke section failed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
