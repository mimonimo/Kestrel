"use client";

import type { UrlObject } from "url";
import {
  ChevronDown,
  ChevronUp,
  Filter,
  Loader2,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";

import { api, type FacetBucket } from "@/lib/api";
import { PIE_PALETTE as SHARED_PIE_PALETTE, PieGroup, type PieSlice } from "@/components/ui/pie-chart";
import { cn } from "@/lib/utils";

type FacetDim = "severity" | "source" | "type" | "domain";
type FacetSelection = Partial<Record<FacetDim, string>>;

const SEV_ORDER = ["critical", "high", "medium", "low"] as const;
const SEV_LABEL: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};
// Hex tints for SVG pie slices.
const SEV_HEX: Record<string, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#34d399",
};

const SOURCE_LABEL: Record<string, string> = {
  mitre: "MITRE",
  nvd: "NVD",
  github_advisory: "GHSA",
  exploit_db: "Exploit-DB",
};
const SOURCE_HEX: Record<string, string> = {
  mitre: "#a78bfa",
  nvd: "#38bdf8",
  github_advisory: "#34d399",
  exploit_db: "#fbbf24",
};

// Re-export the shared palette so existing local callers keep working
// without churn. The actual array lives in components/ui/pie-chart.
const PIE_PALETTE = SHARED_PIE_PALETTE;

const COLLAPSED_KEY = "kestrel:vuln-dist:collapsed"; // '1' | '0'
const PERIOD_KEY = "kestrel:vuln-dist:period"; // PeriodKey

type PeriodKey = "1d" | "7d" | "30d" | "90d" | "all";

const PERIODS: { value: PeriodKey; label: string; days: number | null }[] = [
  { value: "1d", label: "24시간", days: 1 },
  { value: "7d", label: "7일", days: 7 },
  { value: "30d", label: "30일", days: 30 },
  { value: "90d", label: "90일", days: 90 },
  { value: "all", label: "전체", days: null },
];

function periodToWindow(period: PeriodKey): { from?: string; to?: string } {
  const def = PERIODS.find((p) => p.value === period);
  if (!def || def.days === null) return {};
  const from = new Date(Date.now() - def.days * 24 * 60 * 60 * 1000);
  return { from: from.toISOString() };
}

function formatNumber(n: number): string {
  return n.toLocaleString("ko-KR");
}

function formatDay(iso: string | null | undefined): string | null {
  if (!iso) return null;
  return iso.slice(0, 10).replace(/-/g, ".");
}

function topN(buckets: FacetBucket[] | undefined, n: number): FacetBucket[] {
  if (!buckets) return [];
  return [...buckets]
    .filter((b) => b.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, n);
}

interface Slice {
  label: string;
  count: number;
  color: string;
  href?: UrlObject;
  onClick?: () => void;
  selected?: boolean;
  dimmed?: boolean;
  // Underlying value (used to compare against the active selection so
  // labels can be cosmetic).
  rawValue?: string;
}

function buildSlices(
  buckets: FacetBucket[],
  paletteFor: (value: string, idx: number) => string,
  hrefFor?: (value: string) => UrlObject,
  labelFor?: (value: string) => string,
): Slice[] {
  return buckets.map((b, i) => ({
    label: labelFor ? labelFor(b.value) : b.value,
    count: b.count,
    color: paletteFor(b.value, i),
    href: hrefFor ? hrefFor(b.value) : undefined,
    rawValue: b.value,
  }));
}

// Decorate a list of slices with cross-filter behavior — given the
// active selection for this dimension, attach onClick + selected +
// dimmed flags so PieGroup renders the highlight + click toggle.
function withCrossFilter(
  slices: Slice[],
  dim: FacetDim,
  active: string | undefined,
  toggle: (dim: FacetDim, value: string) => void,
): Slice[] {
  return slices.map((s) => {
    const raw = s.rawValue ?? s.label;
    return {
      ...s,
      // Cross-filter replaces the navigate-to-list href — a click here
      // narrows the chart, not the CVE list. Users still get the list
      // filter via FilterPanel chips on the left.
      href: undefined,
      onClick: () => toggle(dim, raw),
      selected: active === raw,
      dimmed: active != null && active !== raw,
    };
  });
}

export function VulnDistributionPanel() {
  const [collapsed, setCollapsed] = useState(false);
  const [period, setPeriod] = useState<PeriodKey>("all");
  // Cross-filter state — clicking a pie slice or legend row toggles
  // that dimension's filter. The backend re-aggregates every other
  // facet against the union of active filters so the entire panel
  // re-tints to reflect the chosen slice. Clicking the same slice
  // again clears just that dimension.
  const [selection, setSelection] = useState<FacetSelection>({});

  const toggleFilter = (dim: FacetDim, value: string) => {
    setSelection((s) => {
      const next: FacetSelection = { ...s };
      if (s[dim] === value) {
        delete next[dim];
      } else {
        next[dim] = value;
      }
      return next;
    });
  };
  const clearFilters = () => setSelection({});
  const activeFilterCount = Object.keys(selection).length;

  // Live polling is derived from period — "전체" (no window) auto-polls
  // every 30s so new ingestions surface in near real time. Bounded
  // windows (24시간/7일/…) skip the poll since the underlying data range
  // is already explicit; refetch happens on tab focus instead.
  const live = period === "all";

  // Recompute the window every render so "24시간" stays a moving window
  // — useMemo gates by `period` only since periodToWindow uses Date.now().
  const window_ = useMemo(() => periodToWindow(period), [period]);

  const facets = useQuery({
    queryKey: [
      "search",
      "facets",
      window_.from ?? "",
      window_.to ?? "",
      selection.severity ?? "",
      selection.source ?? "",
      selection.type ?? "",
      selection.domain ?? "",
    ],
    queryFn: () => api.getSearchFacets(window_, selection),
    staleTime: live ? 0 : 60_000,
    refetchInterval: live ? 30_000 : false,
    refetchIntervalInBackground: false,
    // Keep the previous facet payload on screen while a new query (with
    // changed filters/period) is in flight — without this the panel
    // collapses to the "집계 중…" loader and the layout jumps every
    // time the user toggles a cross-filter, which the user flagged as
    // 깜박임. The header spinner already signals an in-flight fetch.
    placeholderData: keepPreviousData,
  });

  useEffect(() => {
    if (typeof window === "undefined") return;
    setCollapsed(window.localStorage.getItem(COLLAPSED_KEY) === "1");
    const p = window.localStorage.getItem(PERIOD_KEY);
    if (p && PERIODS.some((x) => x.value === p)) setPeriod(p as PeriodKey);
  }, []);

  const setCollapsedPersisted = (c: boolean) => {
    setCollapsed(c);
    if (typeof window !== "undefined") {
      window.localStorage.setItem(COLLAPSED_KEY, c ? "1" : "0");
    }
  };

  const setPeriodPersisted = (p: PeriodKey) => {
    setPeriod(p);
    if (typeof window !== "undefined") window.localStorage.setItem(PERIOD_KEY, p);
  };

  // Only show the standalone loader on the very first load (no prior
  // data has ever resolved). Subsequent re-fetches keep the old data
  // visible via placeholderData so the panel never collapses.
  if (facets.isLoading && !facets.data) {
    return (
      <section className="mb-8 rounded-xl border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-surface-1">
        <div className="flex items-center gap-2 text-sm text-neutral-600 dark:text-neutral-500">
          <Loader2 className="h-4 w-4 animate-spin" /> 수집 분포 집계 중…
        </div>
      </section>
    );
  }
  if (facets.error || !facets.data) {
    return null;
  }
  const data = facets.data;
  // When we're showing previous data while a new query is in flight,
  // softly dim the charts so the user sees that the numbers are still
  // catching up — no layout shift, just a subtle fade.
  const isStale = facets.isPlaceholderData;
  // Authoritative total from backend SELECT COUNT(*); no more summing
  // severities (which excludes unrated rows) or sources (which would
  // double-count multi-source CVEs after PR 10-AF).
  const total = data.total ?? 0;

  const sevByValue = new Map(data.severities?.map((b) => [b.value, b.count]) ?? []);
  const sevSlicesRaw: Slice[] = SEV_ORDER.map((k) => ({
    label: SEV_LABEL[k],
    count: sevByValue.get(k) ?? 0,
    color: SEV_HEX[k],
    rawValue: k,
  })).filter((s) => s.count > 0);
  const sevSlices = withCrossFilter(sevSlicesRaw, "severity", selection.severity, toggleFilter);

  const sourceSlices = withCrossFilter(
    buildSlices(
      topN(data.sources, 6),
      (v) => SOURCE_HEX[v] ?? "#94a3b8",
      undefined,
      (v) => SOURCE_LABEL[v] ?? v,
    ),
    "source",
    selection.source,
    toggleFilter,
  );

  const typeSlices = withCrossFilter(
    buildSlices(topN(data.types, 8), (_v, i) => PIE_PALETTE[i % PIE_PALETTE.length]),
    "type",
    selection.type,
    toggleFilter,
  );

  const domainSlices = withCrossFilter(
    buildSlices(topN(data.domains, 8), (_v, i) => PIE_PALETTE[(i + 3) % PIE_PALETTE.length]),
    "domain",
    selection.domain,
    toggleFilter,
  );

  const dayLo = formatDay(data.earliestPublishedAt);
  const dayHi = formatDay(data.latestPublishedAt);

  const groups: { title: string; slices: Slice[] }[] = [
    {
      title: "심각도",
      slices: sevSlices,
    },
    {
      title: "출처",
      slices: sourceSlices,
    },
    {
      title: "취약점 유형 (상위 8)",
      slices: typeSlices,
    },
    {
      title: "도메인 (상위 8)",
      slices: domainSlices,
    },
  ];

  return (
    <section className="mb-8 rounded-xl border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-surface-1">
      <header className="mb-4 flex flex-wrap items-baseline justify-between gap-3">
        <div className="flex min-w-0 items-baseline gap-2.5">
          <h2 className="text-base font-semibold text-neutral-900 dark:text-neutral-100">
            수집된 취약점 분포
          </h2>
          <span className="tabular-nums text-sm text-neutral-700 dark:text-neutral-400">
            {formatNumber(total)}
            <span className="ml-0.5 text-xs text-neutral-500 dark:text-neutral-600">건</span>
          </span>
          {dayLo && dayHi && (
            <span className="hidden text-[11px] tabular-nums text-neutral-500 dark:text-neutral-600 sm:inline">
              {dayLo} – {dayHi}
            </span>
          )}
          {live && (
            <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 px-1.5 py-0.5 text-[10px] font-medium text-emerald-800 dark:text-emerald-200">
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-500" />
              </span>
              LIVE
            </span>
          )}
          {activeFilterCount > 0 && (
            <span className="inline-flex items-center gap-1 rounded-full bg-sky-500/15 px-1.5 py-0.5 text-[10px] font-medium text-sky-800 dark:text-sky-200">
              <Filter className="h-2.5 w-2.5" />
              필터 {activeFilterCount}
            </span>
          )}
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-1.5">
          {/* Period selector — pill group */}
          <div
            role="group"
            aria-label="집계 기간"
            className="inline-flex overflow-hidden rounded-full border border-neutral-300 bg-white dark:border-neutral-800 dark:bg-surface-2"
          >
            {PERIODS.map((p) => (
              <button
                key={p.value}
                type="button"
                onClick={() => setPeriodPersisted(p.value)}
                className={cn(
                  "px-2.5 py-1 text-[11px] transition-colors",
                  period === p.value
                    ? "bg-sky-100 font-medium text-sky-800 dark:bg-sky-500/20 dark:text-sky-200"
                    : "text-neutral-600 hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-surface-3 dark:hover:text-neutral-100",
                )}
                aria-pressed={period === p.value}
              >
                {p.label}
              </button>
            ))}
          </div>
          {activeFilterCount > 0 && (
            <button
              type="button"
              onClick={clearFilters}
              className="inline-flex items-center gap-1 rounded-full border border-sky-300 bg-sky-50 px-2 py-1 text-[11px] text-sky-800 hover:bg-sky-100 dark:border-sky-500/40 dark:bg-sky-500/10 dark:text-sky-200 dark:hover:bg-sky-500/20"
              title="모든 필터 해제"
            >
              <X className="h-3 w-3" />
              필터 초기화
            </button>
          )}
          {facets.isFetching && (
            <Loader2 className="h-3.5 w-3.5 animate-spin text-sky-600 dark:text-sky-400" />
          )}
          <button
            type="button"
            onClick={() => setCollapsedPersisted(!collapsed)}
            className="inline-flex h-7 w-7 items-center justify-center rounded-full border border-neutral-300 text-neutral-600 hover:bg-neutral-50 hover:text-neutral-900 dark:border-neutral-800 dark:text-neutral-400 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
            aria-expanded={!collapsed}
            aria-label={collapsed ? "펼치기" : "숨기기"}
            title={collapsed ? "펼치기" : "숨기기"}
          >
            {collapsed ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronUp className="h-3.5 w-3.5" />}
          </button>
        </div>
      </header>

      {!collapsed && (
        <div
          className={cn(
            "grid gap-5 transition-opacity duration-200 sm:grid-cols-2 lg:grid-cols-4",
            isStale && "opacity-70",
          )}
          aria-busy={isStale}
        >
          {groups.map((g) => (
            <Group key={g.title} title={g.title}>
              {g.slices.length === 0 ? (
                <p className="text-xs text-neutral-500 dark:text-neutral-600">집계 데이터 없음.</p>
              ) : (
                <PieGroup slices={g.slices} total={total} />
              )}
            </Group>
          ))}
        </div>
      )}
    </section>
  );
}

function Group({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <h3 className="text-[10px] font-semibold uppercase tracking-wider text-neutral-600 dark:text-neutral-500">
        {title}
      </h3>
      {children}
    </div>
  );
}

// Local Slice type is structurally identical to the shared PieSlice — keep
// it as a re-export so existing callers in this file (BarGroup etc.) don't
// need to import from a separate module just to type their arguments.
export type { PieSlice as _PieSliceReexport };
