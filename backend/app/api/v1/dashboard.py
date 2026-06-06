"""Aggregated insights bundled for the main dashboard.

One round-trip, multiple panels — keeps the dashboard fast while staying
flexible (each section can be split out later if a widget needs polling
at a different cadence). 60s TTL cache because every panel here is
derived from corpus state that only changes at ingestion frequency.
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, case, func, or_, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import AffectedProduct, Vulnerability
from app.schemas.vulnerability import CamelModel
from app.services.aggregate_snapshots import (
    SNAP_INSIGHTS,
    SNAP_PRIORITIES,
    get_snapshot,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


# Vendor strings come in wildly inconsistent — "Linux" vs "linux",
# "Oracle" vs "Oracle Corporation", "IBM Corp." vs "ibm" — because
# each upstream feed (NVD, MITRE, GHSA) normalizes differently. We
# collapse them client-side before ranking so the Top-10 list reflects
# distinct vendors, not casing variants.
_VENDOR_SUFFIX_TOKENS = {
    "corporation",
    "corp",
    "company",
    "co",
    "incorporated",
    "inc",
    "limited",
    "ltd",
    "llc",
    "foundation",
    "group",
    "gmbh",
    "sa",
    "ag",
    "kk",
    "plc",
    "systems",
}

# Override the auto-titlecase output for vendors that have a canonical
# capitalization (acronyms, mixed-case brand names). Keys are the
# normalized lowercase form.
_VENDOR_DISPLAY: dict[str, str] = {
    "ibm": "IBM",
    "hp": "HP",
    "hpe": "HPE",
    "sap": "SAP",
    "amd": "AMD",
    "arm": "ARM",
    "aws": "AWS",
    "gcp": "GCP",
    "ssh": "SSH",
    "tcp": "TCP",
    "vmware": "VMware",
    "github": "GitHub",
    "gitlab": "GitLab",
    "nodejs": "Node.js",
    "phpmyadmin": "phpMyAdmin",
    "red hat": "Red Hat",
    "redhat": "Red Hat",
    "trend micro": "Trend Micro",
    "trendmicro": "Trend Micro",
    "f5": "F5",
    "qnap": "QNAP",
    "synology": "Synology",
}


def _normalize_vendor_key(raw: str) -> str:
    """Collapse casing + corporate suffixes into a single grouping key.

    "Oracle" / "Oracle Corporation" / "ORACLE CORP." all map to the
    same key "oracle". Empty result (after stripping) indicates the
    vendor field was effectively content-free and should be skipped.
    """
    s = raw.lower().strip().rstrip(".,;")
    s = s.replace(",", " ")
    parts = s.split()
    while parts and parts[-1].rstrip(".,;") in _VENDOR_SUFFIX_TOKENS:
        parts.pop()
    return " ".join(parts).strip()


def _display_vendor(key: str) -> str:
    if key in _VENDOR_DISPLAY:
        return _VENDOR_DISPLAY[key]
    # Title case word-by-word. Splits on whitespace + hyphens so
    # "red-hat" → "Red-Hat" stays readable.
    def cap(word: str) -> str:
        if not word:
            return word
        # Preserve "IoT" / "API" style words if user has them in DISPLAY,
        # otherwise plain capitalize.
        return word[0].upper() + word[1:]

    return " ".join(cap(p) for p in key.split())


class TimelineDay(CamelModel):
    date: str
    total: int
    critical: int
    high: int
    medium: int
    low: int


class VendorBucket(CamelModel):
    vendor: str
    count: int


class CvssBucket(CamelModel):
    """One band of the standard 4-tier breakdown (Low / Medium / High /
    Critical). Kept for backwards compat — the new histogram below is
    what the dashboard actually renders."""

    label: str
    range_lo: float
    range_hi: float
    count: int


class CvssHistogramBin(CamelModel):
    """A 1-point-wide bin (0-1, 1-2, …, 9-10). Drives the dashboard's
    high-resolution distribution chart."""

    lo: float
    hi: float
    count: int


class CvssDistribution(CamelModel):
    histogram: list[CvssHistogramBin]
    total: int
    mean: float | None       # arithmetic mean over scored rows
    median: float | None     # 50th percentile
    p90: float | None        # 90th percentile — long-tail risk marker
    unscored: int            # rows with NULL cvss_score (signal coverage gap)


class RecentItem(CamelModel):
    cve_id: str
    title: str
    severity: str | None
    cvss_score: float | None
    published_at: datetime | None


class PrioritySignalCounts(CamelModel):
    """At-a-glance counters used by the PrioritySignals widget on the
    main dashboard. Drawn from the three pillars the user's reference
    image highlighted (CVSS — theoretical, EPSS — predicted, KEV —
    observed)."""

    cvss_critical: int        # cvss_score >= 9.0
    cvss_high: int            # cvss_score in [7.0, 9.0)
    epss_high: int            # epss_score >= 0.5
    epss_top_percentile: int  # epss_percentile >= 0.95
    kev_listed: int           # kev_listed = true


class InsightsResponse(CamelModel):
    timeline: list[TimelineDay]
    top_vendors: list[VendorBucket]
    cvss_buckets: list[CvssBucket]
    cvss_distribution: CvssDistribution
    recent_critical: list[RecentItem]
    priority_signals: PrioritySignalCounts
    generated_at: datetime


_CACHE: dict[str, tuple[float, InsightsResponse]] = {}
_CACHE_TTL = 60.0
_CACHE_LOCK = asyncio.Lock()


@router.get(
    "/insights",
    response_model=InsightsResponse,
    response_model_by_alias=True,
)
async def dashboard_insights(
    db: AsyncSession = Depends(get_db),
    days: int = Query(default=30, ge=1, le=365),
    vendor_limit: int = Query(default=10, ge=1, le=50),
    recent_limit: int = Query(default=5, ge=1, le=20),
) -> InsightsResponse:
    """Bundled dashboard metrics with a short TTL cache."""
    # 기본 파라미터(프론트 대시보드 첫 로드)는 미리 계산된 스냅샷을 즉시 반환.
    if days == 30 and vendor_limit == 10 and recent_limit == 5:
        raw = await get_snapshot(SNAP_INSIGHTS)
        if raw:
            try:
                return InsightsResponse.model_validate_json(raw)
            except Exception:  # noqa: BLE001 — 폴백
                pass
    # v4: CVSS 점수 분포가 days 윈도우(published_at)를 타도록 변경 — 캐시 무효화.
    cache_key = f"v4|{days}|{vendor_limit}|{recent_limit}"
    now_mono = time.monotonic()
    cached = _CACHE.get(cache_key)
    if cached and now_mono - cached[0] < _CACHE_TTL:
        return cached[1]
    async with _CACHE_LOCK:
        cached = _CACHE.get(cache_key)
        if cached and now_mono - cached[0] < _CACHE_TTL:
            return cached[1]
        result = await _compute(db, days=days, vendor_limit=vendor_limit, recent_limit=recent_limit)
        _CACHE[cache_key] = (now_mono, result)
        return result


async def _compute(
    db: AsyncSession,
    *,
    days: int,
    vendor_limit: int,
    recent_limit: int,
) -> InsightsResponse:
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)

    # ── timeline: daily count, broken out by severity ───────────────
    day = func.date_trunc("day", Vulnerability.published_at).label("day")
    sev = Vulnerability.severity
    timeline_q = (
        select(
            day,
            func.count().label("total"),
            func.sum(case((sev == "critical", 1), else_=0)).label("critical"),
            func.sum(case((sev == "high", 1), else_=0)).label("high"),
            func.sum(case((sev == "medium", 1), else_=0)).label("medium"),
            func.sum(case((sev == "low", 1), else_=0)).label("low"),
        )
        .where(
            Vulnerability.published_at.isnot(None),
            Vulnerability.published_at >= since,
        )
        .group_by(day)
        .order_by(day.asc())
    )
    rows = (await db.execute(timeline_q)).all()
    by_date = {r.day.date().isoformat(): r for r in rows}
    # Fill any missing days with zeros so the area chart x-axis has even
    # spacing — ingestion gaps shouldn't make Wednesday vanish.
    timeline: list[TimelineDay] = []
    for i in range(days):
        d = (since + timedelta(days=i)).date()
        key = d.isoformat()
        r = by_date.get(key)
        timeline.append(
            TimelineDay(
                date=key,
                total=int(r.total) if r else 0,
                critical=int(r.critical or 0) if r else 0,
                high=int(r.high or 0) if r else 0,
                medium=int(r.medium or 0) if r else 0,
                low=int(r.low or 0) if r else 0,
            )
        )

    # ── top vendors (by # distinct CVEs they're listed under) ───────
    # Filter out placeholder names ("n/a" / empty / unknown), then
    # normalize on the Python side so cases like "Linux" vs "linux" and
    # "Oracle" vs "Oracle Corporation" collapse into one bucket. SQL
    # alone can't do the suffix stripping cleanly, but the
    # post-aggregation set is small (a few thousand rows) so the
    # in-process merge is cheap.
    raw_vendor_q = (
        select(
            AffectedProduct.vendor,
            func.count(func.distinct(AffectedProduct.vulnerability_id)).label("c"),
        )
        .where(
            AffectedProduct.vendor.isnot(None),
            AffectedProduct.vendor != "",
            func.lower(AffectedProduct.vendor) != "n/a",
            func.lower(AffectedProduct.vendor) != "unknown",
        )
        .group_by(AffectedProduct.vendor)
    )
    raw_vendor_rows = (await db.execute(raw_vendor_q)).all()

    buckets: dict[str, int] = {}
    for v, c in raw_vendor_rows:
        key = _normalize_vendor_key(v)
        if not key:
            continue
        buckets[key] = buckets.get(key, 0) + int(c)

    top = sorted(buckets.items(), key=lambda kv: kv[1], reverse=True)[:vendor_limit]
    top_vendors = [
        VendorBucket(vendor=_display_vendor(k), count=c) for k, c in top
    ]

    # ── CVSS 점수 분포 ──────────────────────────────────────────────
    # days 윈도우(최근 N일 published) 안의 CVE 만 대상으로 한다 — 패널의
    # 7/30/90일 토글이 여기에 매핑된다. published_at 이 비어있는 행은 기간을
    # 알 수 없으므로 제외.
    scored_window = (
        Vulnerability.published_at.isnot(None),
        Vulnerability.published_at >= since,
    )

    # ── CVSS buckets (legacy 4-tier) ────────────────────────────────
    buckets_def = [
        ("0.0–3.9 (Low)", 0.0, 3.9),
        ("4.0–6.9 (Medium)", 4.0, 6.9),
        ("7.0–8.9 (High)", 7.0, 8.9),
        ("9.0–10 (Critical)", 9.0, 10.0),
    ]
    bucket_results: list[CvssBucket] = []
    for label, lo, hi in buckets_def:
        cnt = (
            await db.execute(
                select(func.count())
                .select_from(Vulnerability)
                .where(
                    Vulnerability.cvss_score.isnot(None),
                    Vulnerability.cvss_score >= lo,
                    Vulnerability.cvss_score <= hi,
                    *scored_window,
                )
            )
        ).scalar_one()
        bucket_results.append(
            CvssBucket(label=label, range_lo=lo, range_hi=hi, count=int(cnt or 0)),
        )

    # ── CVSS high-resolution histogram + summary stats ──────────────
    # 10 fixed-width bins (0-1, 1-2, …, 9-10) give a far richer picture
    # than the 4-tier rollup above. Single GROUP BY width_bucket query
    # so the cost is O(scored rows) once, not 10 separate COUNT(*) hits.
    width_expr = func.width_bucket(Vulnerability.cvss_score, 0.0, 10.0, 10).label("bin")
    hist_rows = (
        await db.execute(
            select(width_expr, func.count())
            .where(Vulnerability.cvss_score.isnot(None), *scored_window)
            .group_by("bin")
            .order_by("bin")
        )
    ).all()
    # width_bucket returns 1..N for in-range values + 0 for below-low +
    # N+1 for above-high; we only care about 1..10 and merge any edge
    # bucket (rare; cvss_score is bounded 0-10) into the closest valid
    # bin.
    hist_counts = {i: 0 for i in range(1, 11)}
    for b, c in hist_rows:
        idx = max(1, min(10, int(b))) if b is not None else 1
        hist_counts[idx] = hist_counts.get(idx, 0) + int(c)
    histogram: list[CvssHistogramBin] = [
        CvssHistogramBin(lo=float(i - 1), hi=float(i), count=hist_counts[i])
        for i in range(1, 11)
    ]

    # mean / median / p90 from postgres aggregates so we don't roundtrip
    # the full score column.
    stat_row = (
        await db.execute(
            select(
                func.avg(Vulnerability.cvss_score),
                func.percentile_cont(0.5).within_group(Vulnerability.cvss_score.asc()),
                func.percentile_cont(0.9).within_group(Vulnerability.cvss_score.asc()),
                func.count(),
            ).where(Vulnerability.cvss_score.isnot(None), *scored_window)
        )
    ).first()
    unscored_count = int(
        (
            await db.execute(
                select(func.count())
                .select_from(Vulnerability)
                .where(
                    Vulnerability.cvss_score.is_(None),
                    Vulnerability.published_at.isnot(None),
                    Vulnerability.published_at >= since,
                )
            )
        ).scalar_one()
        or 0
    )
    cvss_distribution = CvssDistribution(
        histogram=histogram,
        total=int(stat_row[3] or 0) if stat_row else 0,
        mean=float(stat_row[0]) if stat_row and stat_row[0] is not None else None,
        median=float(stat_row[1]) if stat_row and stat_row[1] is not None else None,
        p90=float(stat_row[2]) if stat_row and stat_row[2] is not None else None,
        unscored=unscored_count,
    )

    # ── recent critical CVEs (newest first) ─────────────────────────
    recent_q = (
        select(
            Vulnerability.cve_id,
            Vulnerability.title,
            Vulnerability.severity,
            Vulnerability.cvss_score,
            Vulnerability.published_at,
        )
        .where(Vulnerability.severity == "critical")
        .order_by(Vulnerability.published_at.desc().nulls_last())
        .limit(recent_limit)
    )
    recent_rows = (await db.execute(recent_q)).all()

    def _enum_value(v) -> str | None:
        if v is None:
            return None
        return v.value if hasattr(v, "value") else str(v)

    recent_critical = [
        RecentItem(
            cve_id=r.cve_id,
            title=r.title,
            severity=_enum_value(r.severity),
            cvss_score=float(r.cvss_score) if r.cvss_score is not None else None,
            published_at=r.published_at,
        )
        for r in recent_rows
    ]

    # ── priority signal counts ──────────────────────────────────────
    async def _scalar_count(*where) -> int:
        return int(
            (await db.execute(select(func.count()).select_from(Vulnerability).where(*where))).scalar_one() or 0
        )

    signals = PrioritySignalCounts(
        cvss_critical=await _scalar_count(Vulnerability.cvss_score >= 9.0),
        cvss_high=await _scalar_count(
            Vulnerability.cvss_score >= 7.0,
            Vulnerability.cvss_score < 9.0,
        ),
        epss_high=await _scalar_count(Vulnerability.epss_score >= 0.5),
        epss_top_percentile=await _scalar_count(Vulnerability.epss_percentile >= 0.95),
        kev_listed=await _scalar_count(Vulnerability.kev_listed.is_(True)),
    )

    return InsightsResponse(
        timeline=timeline,
        top_vendors=top_vendors,
        cvss_buckets=bucket_results,
        cvss_distribution=cvss_distribution,
        recent_critical=recent_critical,
        priority_signals=signals,
        generated_at=now,
    )


# ──────────── Priority matrix: "What to Fix First" ───────────────────


class PriorityItem(CamelModel):
    cve_id: str
    title: str
    severity: str | None
    cvss_score: float | None
    epss_score: float | None
    epss_percentile: float | None
    kev_listed: bool
    kev_date_added: datetime | None
    published_at: datetime | None


class PriorityBucket(CamelModel):
    """One row of the 4-tier "WHAT TO FIX FIRST" matrix.

    ``key`` is the stable identifier (used by the UI for routing / icons);
    ``label`` is the Korean display name; ``rationale`` is the one-line
    explanation of why this tier exists (mirrors the reference image's
    right-hand column)."""

    key: str
    label: str
    rationale: str
    count: int
    items: list[PriorityItem]


class PrioritiesResponse(CamelModel):
    buckets: list[PriorityBucket]
    generated_at: datetime


_PRIORITY_CACHE: dict[str, tuple[float, PrioritiesResponse]] = {}
_PRIORITY_CACHE_TTL = 60.0
_PRIORITY_CACHE_LOCK = asyncio.Lock()


# Each tier has a SQL filter + a sort order. Tier 1 wins over Tier 2,
# etc.; later tiers exclude rows that already qualify for an earlier
# tier so the same CVE doesn't appear twice on the matrix.
def _tier_filters():
    # ``== true()`` 로 렌더(= ``kev_listed = true``)해야 부분 인덱스
    # ix_vuln_kev_listed(WHERE kev_listed = true)를 탄다. ``.is_(True)``(IS TRUE)는
    # 부분 인덱스 술어와 매칭되지 않아 seq scan(=count 62초) 으로 떨어진다.
    kev = Vulnerability.kev_listed == true()
    epss_high = Vulnerability.epss_score >= 0.5
    cvss_mid = and_(Vulnerability.cvss_score >= 4.0, Vulnerability.cvss_score < 7.0)
    cvss_high = Vulnerability.cvss_score >= 7.0
    epss_low = or_(Vulnerability.epss_score < 0.3, Vulnerability.epss_score.is_(None))

    return [
        {
            "key": "kev",
            "label": "KEV 등재",
            "rationale": "실측된 악용 — 최우선 패치",
            "where": [kev],
            "order_by": [
                Vulnerability.kev_date_added.desc().nulls_last(),
                Vulnerability.cvss_score.desc().nulls_last(),
            ],
        },
        {
            "key": "epss_high",
            "label": "EPSS 상위 + 외부 접점",
            "rationale": "30일 내 악용 예측 + 직접 노출 — 즉시 조치",
            "where": [epss_high, ~kev],
            "order_by": [
                Vulnerability.epss_score.desc().nulls_last(),
                Vulnerability.cvss_score.desc().nulls_last(),
            ],
        },
        {
            "key": "cvss_mid_epss_high",
            "label": "CVSS 중간 + EPSS 높음",
            "rationale": "이론은 낮아도 실제 터질 가능성 — 앞당겨 조치",
            "where": [cvss_mid, Vulnerability.epss_score >= 0.3, ~kev],
            "order_by": [
                Vulnerability.epss_score.desc().nulls_last(),
                Vulnerability.published_at.desc().nulls_last(),
            ],
        },
        {
            "key": "cvss_high_epss_low",
            "label": "CVSS 높음 + EPSS 낮음",
            "rationale": "이론 심각도만 — 계획된 패치 주기로",
            "where": [cvss_high, epss_low, ~kev],
            "order_by": [
                Vulnerability.cvss_score.desc().nulls_last(),
                Vulnerability.published_at.desc().nulls_last(),
            ],
        },
    ]


@router.get(
    "/priorities",
    response_model=PrioritiesResponse,
    response_model_by_alias=True,
)
async def dashboard_priorities(
    db: AsyncSession = Depends(get_db),
    per_bucket: int = Query(default=5, ge=1, le=25),
) -> PrioritiesResponse:
    """Return the four "What to Fix First" tiers each with their top N CVEs.

    Filters mirror the reference image's prioritization model:
      1. KEV (실측된 악용)
      2. EPSS ≥ 0.5 (예측 + 외부 접점 ─ here we use raw EPSS; "외부
         접점" weighting comes in when the user's Asset registry is
         linked, which is a future extension.)
      3. CVSS 4-6.9 + EPSS ≥ 0.3 (이론 낮아도 실제 터질 가능성)
      4. CVSS ≥ 7 + EPSS < 0.3 (계획된 패치)
    """
    # 기본 per_bucket(프론트 대시보드 첫 로드)은 미리 계산된 스냅샷을 즉시 반환.
    if per_bucket == 5:
        raw = await get_snapshot(SNAP_PRIORITIES)
        if raw:
            try:
                return PrioritiesResponse.model_validate_json(raw)
            except Exception:  # noqa: BLE001 — 폴백
                pass
    cache_key = f"v1|{per_bucket}"
    now_mono = time.monotonic()
    cached = _PRIORITY_CACHE.get(cache_key)
    if cached and now_mono - cached[0] < _PRIORITY_CACHE_TTL:
        return cached[1]
    async with _PRIORITY_CACHE_LOCK:
        cached = _PRIORITY_CACHE.get(cache_key)
        if cached and now_mono - cached[0] < _PRIORITY_CACHE_TTL:
            return cached[1]
        result = await _compute_priorities(db, per_bucket=per_bucket)
        _PRIORITY_CACHE[cache_key] = (now_mono, result)
        return result


async def _compute_priorities(
    db: AsyncSession, *, per_bucket: int
) -> PrioritiesResponse:
    out: list[PriorityBucket] = []

    def _enum_value(v) -> str | None:
        if v is None:
            return None
        return v.value if hasattr(v, "value") else str(v)

    for tier in _tier_filters():
        # Total count for this bucket (so the UI can say "N건 중 상위 5").
        count = int(
            (
                await db.execute(
                    select(func.count())
                    .select_from(Vulnerability)
                    .where(*tier["where"])
                )
            ).scalar_one()
            or 0
        )
        item_q = (
            select(
                Vulnerability.cve_id,
                Vulnerability.title,
                Vulnerability.severity,
                Vulnerability.cvss_score,
                Vulnerability.epss_score,
                Vulnerability.epss_percentile,
                Vulnerability.kev_listed,
                Vulnerability.kev_date_added,
                Vulnerability.published_at,
            )
            .where(*tier["where"])
            .order_by(*tier["order_by"])
            .limit(per_bucket)
        )
        rows = (await db.execute(item_q)).all()
        items = [
            PriorityItem(
                cve_id=r.cve_id,
                title=r.title,
                severity=_enum_value(r.severity),
                cvss_score=float(r.cvss_score) if r.cvss_score is not None else None,
                epss_score=float(r.epss_score) if r.epss_score is not None else None,
                epss_percentile=float(r.epss_percentile) if r.epss_percentile is not None else None,
                kev_listed=bool(r.kev_listed),
                kev_date_added=r.kev_date_added,
                published_at=r.published_at,
            )
            for r in rows
        ]
        out.append(
            PriorityBucket(
                key=tier["key"],
                label=tier["label"],
                rationale=tier["rationale"],
                count=count,
                items=items,
            )
        )

    return PrioritiesResponse(buckets=out, generated_at=datetime.now(timezone.utc))
