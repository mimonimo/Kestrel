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
import itertools
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
# FIRST publishes a daily snapshot at this stable URL (hosted by Empirical
# Security; the old epss.cyentia.com host now just 301-redirects here, so we
# point at the canonical host directly instead of relying on that redirect).
# Always the most recent run; no rolling window math needed on our side.
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

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


def _chunked(it: Iterable, size: int):
    """Yield lists of up to ``size`` items from an iterable, holding only
    one chunk in memory at a time. Lets us stream the ~340k EPSS rows into
    staging without ever materializing the whole set as a Python list."""
    iterator = iter(it)
    while True:
        chunk = list(itertools.islice(iterator, size))
        if not chunk:
            return
        yield chunk


async def refresh_epss(insert_batch: int = 5000, update_batch: int = 20000) -> dict:
    """Download the daily EPSS snapshot and update our rows.

    ~340k rows. The production host is memory-tight (1.8GB, 5 containers),
    so we keep the footprint small at every step:
      - parse + stage in streaming chunks (never hold the full row set in a
        Python list);
      - apply score changes in keyset-paginated batches with a commit per
        batch, so no single statement rewrites ~340k rows at once.
    The previous single big UPDATE took ~150s and rewrote ~all rows in one
    transaction; under concurrent load (e.g. right after a deploy) that
    overran memory and the job was OOM-killed, leaving EPSS stale. Batching
    trades all-or-nothing atomicity for memory safety — a partially-applied
    run is self-healing on the next pass. Rows whose CVE we don't have in
    our corpus are silently skipped (no INSERT — see module docstring).
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

    now = datetime.now(timezone.utc)

    async with SessionLocal() as session:
        # 스테이징 — keyset 배치 UPDATE 가 커밋 사이에도 유지돼야 하므로
        # ON COMMIT PRESERVE ROWS. 이전 실행 잔재(풀 재사용 커넥션)는 시작 시 제거.
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
        # 스트리밍 적재 — 제너레이터를 청크로 끊어 넣어 340k 행을 한꺼번에
        # 파이썬 메모리에 올리지 않는다.
        fetched = 0
        for chunk in _chunked(_iter_epss_rows(blob), insert_batch):
            await session.execute(
                text(
                    "INSERT INTO _epss_staging (cve_id, score, percentile) "
                    "VALUES (:cve, :score, :pct) "
                    "ON CONFLICT (cve_id) DO UPDATE SET "
                    "score = EXCLUDED.score, percentile = EXCLUDED.percentile"
                ),
                [{"cve": c, "score": s, "pct": p} for c, s, p in chunk],
            )
            fetched += len(chunk)
        await session.commit()  # 스테이징 적재 확정
        result["fetched"] = fetched
        if fetched == 0:
            result["error"] = "EPSS CSV was empty (parse failure?)"
            return result

        # 변경된 행만, cve_id keyset 페이지네이션으로 배치 갱신.
        #  - 단일 대형 UPDATE(340k행, ~150s)는 1.8GB 박스에서 메모리/WAL/락을
        #    과점해 동시 부하 시 OOM 으로 죽었다(운영 장애 원인).
        #  - staging 의 cve_id PK 인덱스로 정렬해 한 번에 update_batch 행씩만
        #    조인·갱신하고 배치마다 커밋 → WAL·락·메모리 점유를 상한으로 묶는다.
        #  - IS DISTINCT FROM 으로 실제 점수가 바뀐 행만 재기록(일일 차분 최소화).
        #  데이터 수정 CTE: batch 스냅샷을 upd(UPDATE)와 집계 SELECT 가 함께 보며,
        #  seen<배치크기면 마지막 페이지이므로 종료(마지막 부분 배치도 이미 적용됨).
        matched = 0
        last_cve = ""
        while True:
            row = (
                await session.execute(
                    text(
                        "WITH batch AS ("
                        "  SELECT cve_id, score, percentile FROM _epss_staging "
                        "  WHERE cve_id > :last ORDER BY cve_id LIMIT :n"
                        "), upd AS ("
                        "  UPDATE vulnerabilities v "
                        "  SET epss_score = s.score, "
                        "      epss_percentile = s.percentile, "
                        "      epss_updated_at = :now "
                        "  FROM batch s "
                        "  WHERE v.cve_id = s.cve_id "
                        "    AND (v.epss_score IS DISTINCT FROM s.score "
                        "         OR v.epss_percentile IS DISTINCT FROM s.percentile) "
                        "  RETURNING 1"
                        ") "
                        "SELECT (SELECT count(*) FROM batch) AS seen, "
                        "       (SELECT max(cve_id) FROM batch) AS last_cve, "
                        "       (SELECT count(*) FROM upd) AS changed"
                    ),
                    {"last": last_cve, "n": update_batch, "now": now},
                )
            ).one()
            seen = int(row.seen or 0)
            matched += int(row.changed or 0)
            await session.commit()  # 배치마다 WAL/락 해제
            if seen < update_batch or row.last_cve is None:
                break
            last_cve = row.last_cve
        result["matched"] = matched

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
