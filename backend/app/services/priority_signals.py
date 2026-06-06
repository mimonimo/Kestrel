"""Priority-signal collectors — CISA KEV + FIRST EPSS.

Both feeds enrich existing Vulnerability rows in place (set
``kev_listed`` / ``epss_score`` / ``epss_percentile`` / dates). They do
NOT create new CVE rows — a CVE has to be in our corpus first for the
signal to land. That's correct behavior: KEV/EPSS without the base
record (description, affected products) isn't actionable.

Run cadence:
- KEV: refreshed several times a day by CISA. We hit it on every
  scheduler tick (cheap, ~1MB JSON).
- EPSS: refreshed daily by FIRST. ~5MB gzipped CSV; we pull once per
  day from the scheduler and on-demand via the admin endpoint.
"""
from __future__ import annotations

import csv
import gzip
import io
from datetime import date, datetime, timezone
from typing import Iterable

import httpx
from sqlalchemy import text, update

from app.core.database import SessionLocal
from app.core.logging import get_logger
from app.models import Vulnerability

log = get_logger(__name__)


KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
# FIRST publishes a daily snapshot at this stable URL. Always the most
# recent run; no rolling window math needed on our side.
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

_HTTP_TIMEOUT = httpx.Timeout(60.0, connect=15.0)


# ───────────────────────── KEV ───────────────────────────────────────


def _parse_kev_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


async def refresh_kev() -> dict:
    """Pull the current CISA KEV catalog and mark matching rows.

    Returns {"fetched": N, "matched": M, "unmatched": K, "error": ...}
    """
    started = datetime.now(timezone.utc)
    result: dict = {"source": "kev", "fetched": 0, "matched": 0, "unmatched": 0, "error": None}

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(KEV_URL, headers={"Accept": "application/json"})
            resp.raise_for_status()
            payload = resp.json()
    except Exception as e:  # noqa: BLE001 — surface network/JSON issues alike
        result["error"] = f"{type(e).__name__}: {e}"
        log.warning("kev.fetch_failed", error=result["error"])
        return result

    vulns = payload.get("vulnerabilities", [])
    result["fetched"] = len(vulns)

    # KEV rows we want to insert: cve_id → (date_added, due_date)
    kev_map: dict[str, tuple[date | None, date | None]] = {}
    for v in vulns:
        cve_id = (v.get("cveID") or "").strip()
        if not cve_id:
            continue
        kev_map[cve_id] = (
            _parse_kev_date(v.get("dateAdded")),
            _parse_kev_date(v.get("dueDate")),
        )

    if not kev_map:
        log.info("kev.empty_payload")
        return result

    async with SessionLocal() as session:
        # First reset everything (so de-listed CVEs go back to False).
        # The KEV catalog is small enough that this is cheap.
        await session.execute(
            update(Vulnerability)
            .where(Vulnerability.kev_listed.is_(True))
            .values(kev_listed=False, kev_date_added=None, kev_due_date=None)
        )

        # Then re-mark every CVE that's currently in the catalog AND in
        # our corpus. CVEs in the catalog but not yet ingested simply
        # don't get a row update — they'll pick up the flag the next
        # time the KEV refresh runs after their base ingestion lands.
        for cve_id, (added, due) in kev_map.items():
            r = await session.execute(
                update(Vulnerability)
                .where(Vulnerability.cve_id == cve_id)
                .values(
                    kev_listed=True,
                    kev_date_added=added,
                    kev_due_date=due,
                )
                .returning(Vulnerability.id)
            )
            if r.first() is not None:
                result["matched"] += 1
            else:
                result["unmatched"] += 1

        await session.commit()

    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
    log.info(
        "kev.refresh_done",
        elapsed=f"{elapsed:.1f}s",
        **{k: v for k, v in result.items() if k != "error"},
    )
    return result


# ───────────────────────── EPSS ──────────────────────────────────────


def _iter_epss_rows(raw_gzipped: bytes) -> Iterable[tuple[str, float, float]]:
    """Yield ``(cve_id, score, percentile)`` from the FIRST CSV bytes.

    The CSV has a single-line "#model_version,score_date" comment header
    before the column header; csv.reader handles that fine as long as we
    skip the first line manually.
    """
    with gzip.GzipFile(fileobj=io.BytesIO(raw_gzipped)) as gz:
        text = io.TextIOWrapper(gz, encoding="utf-8")
        first = text.readline()  # noqa: F841 — model_version / date stamp
        reader = csv.DictReader(text)
        for row in reader:
            cve = (row.get("cve") or "").strip()
            try:
                score = float(row.get("epss") or "0")
                pct = float(row.get("percentile") or "0")
            except ValueError:
                continue
            if not cve:
                continue
            yield cve, score, pct


async def refresh_epss(batch_size: int = 2000) -> dict:
    """Download the daily EPSS snapshot and update our rows.

    ~300k rows; we batch the UPDATE so we don't blow up the transaction
    log. Rows whose CVE we don't have in our corpus are silently skipped
    (no INSERT — see module docstring).
    """
    started = datetime.now(timezone.utc)
    result: dict = {"source": "epss", "fetched": 0, "matched": 0, "error": None}

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(EPSS_URL, follow_redirects=True)
            resp.raise_for_status()
            blob = resp.content
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"
        log.warning("epss.fetch_failed", error=result["error"])
        return result

    rows = list(_iter_epss_rows(blob))
    result["fetched"] = len(rows)
    if not rows:
        result["error"] = "EPSS CSV was empty (parse failure?)"
        return result

    now = datetime.now(timezone.utc)

    async with SessionLocal() as session:
        # 스테이징 — 배치 UPDATE 를 여러 트랜잭션으로 나누려면 커밋 사이에도
        # 유지돼야 하므로 ON COMMIT PRESERVE ROWS. 이전 실행 잔재(풀 재사용
        # 커넥션)는 시작 시 제거.
        await session.execute(text("DROP TABLE IF EXISTS _epss_staging"))
        await session.execute(
            text(
                "CREATE TEMP TABLE _epss_staging ("
                " cve_id text PRIMARY KEY,"
                " score double precision NOT NULL,"
                " percentile double precision NOT NULL"
                ") ON COMMIT PRESERVE ROWS"
            )
        )
        for i in range(0, len(rows), batch_size):
            chunk = rows[i : i + batch_size]
            await session.execute(
                text(
                    "INSERT INTO _epss_staging (cve_id, score, percentile) "
                    "VALUES (:cve, :score, :pct) "
                    "ON CONFLICT (cve_id) DO UPDATE SET "
                    "score = EXCLUDED.score, percentile = EXCLUDED.percentile"
                ),
                [{"cve": c, "score": s, "pct": p} for c, s, p in chunk],
            )
        await session.commit()  # 스테이징 적재 확정

        # 변경된 행만 한 번에 갱신 (perf-A).
        #  - 기존: 매일 ~30만 행을 *전부* 재기록 → 20분간 락/WAL/디스크 점유.
        #  - 변경: epss_score/percentile 이 실제로 바뀐 행만(IS DISTINCT FROM)
        #    재기록한다. 조인 스캔은 1회(staging PK + vulnerabilities cveId 인덱스)
        #    이고, MVCC 행 재기록·인덱스 갱신·WAL 은 "바뀐 행 수"에 비례하므로
        #    일상적인 일일 차분에선 재기록량이 급감한다(매일 30만 → 변동분만).
        #  주의: 배치 루프(LIMIT)로 쪼개면 변동분이 적을 때 매 배치가 조인 전체를
        #  스캔해 오히려 느려진다 — 단일 statement 가 정답.
        updated = await session.execute(
            text(
                "UPDATE vulnerabilities v "
                "SET epss_score = s.score, "
                "    epss_percentile = s.percentile, "
                "    epss_updated_at = :now "
                "FROM _epss_staging s "
                "WHERE v.cve_id = s.cve_id "
                "  AND (v.epss_score IS DISTINCT FROM s.score "
                "       OR v.epss_percentile IS DISTINCT FROM s.percentile)"
            ),
            {"now": now},
        )
        result["matched"] = int(updated.rowcount or 0)
        await session.commit()

        await session.execute(text("DROP TABLE IF EXISTS _epss_staging"))
        await session.commit()

    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
    log.info(
        "epss.refresh_done",
        elapsed=f"{elapsed:.1f}s",
        **{k: v for k, v in result.items() if k != "error"},
    )
    return result


async def refresh_all() -> dict:
    """Convenience wrapper: KEV then EPSS, returning both reports."""
    kev = await refresh_kev()
    epss = await refresh_epss()
    return {"kev": kev, "epss": epss}
