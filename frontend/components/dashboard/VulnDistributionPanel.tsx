"use client";

import Link from "next/link";
import type { UrlObject } from "url";
import {
  Activity,
  BarChart3,
  ChevronDown,
  ChevronUp,
  Loader2,
  Pause,
  PieChart,
  Play,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { api, type FacetBucket } from "@/lib/api";
import { PIE_PALETTE as SHARED_PIE_PALETTE, PieGroup, type PieSlice } from "@/components/ui/pie-chart";
import { cn } from "@/lib/utils";

const SEV_ORDER = ["critical", "high", "medium", "low"] as const;
const SEV_LABEL: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};
// Hex tints for SVG pie slices + matching tailwind bg classes for bars.
const SEV_HEX: Record<string, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#34d399",
};
const SEV_BAR_TINT: Record<string, string> = {
  critical: "bg-rose-500/80",
  high: "bg-orange-400/80",
  medium: "bg-amber-300/70",
  low: "bg-emerald-400/70",
};
const SEV_TEXT: Record<string, string> = {
  critical: "text-rose-700 dark:text-rose-300",
  high: "text-orange-700 dark:text-orange-300",
  medium: "text-amber-700 dark:text-amber-300",
  low: "text-emerald-700 dark:text-emerald-300",
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
const SOURCE_TINT: Record<string, string> = {
  mitre: "bg-violet-500/80",
  nvd: "bg-sky-500/80",
  github_advisory: "bg-emerald-500/80",
  exploit_db: "bg-amber-500/80",
};

// Re-export the shared palette so existing local callers keep working
// without churn. The actual array lives in components/ui/pie-chart.
const PIE_PALETTE = SHARED_PIE_PALETTE;

const VIEW_KEY = "kestrel:vuln-dist:view"; // 'bar' | 'pie'
const COLLAPSED_KEY = "kestrel:vuln-dist:collapsed"; // '1' | '0'
const PERIOD_KEY = "kestrel:vuln-dist:period"; // PeriodKey
const LIVE_KEY = "kestrel:vuln-dist:live"; // '1' | '0'

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
  }));
}

export function VulnDistributionPanel() {
  const [view, setView] = useState<"bar" | "pie">("bar");
  const [collapsed, setCollapsed] = useState(false);
  const [period, setPeriod] = useState<PeriodKey>("all");
  const [live, setLive] = useState(false);

  // Recompute the window every render so "24시간" stays a moving window
  // — useMemo gates by `period` only since periodToWindow uses Date.now().
  const window_ = useMemo(() => periodToWindow(period), [period]);

  const facets = useQuery({
    queryKey: ["search", "facets", window_.from ?? "", window_.to ?? ""],
    queryFn: () => api.getSearchFacets(window_),
    staleTime: live ? 0 : 60_000,
    refetchInterval: live ? 30_000 : false,
    refetchIntervalInBackground: false,
  });

  useEffect(() => {
    if (typeof window === "undefined") return;
    const v = window.localStorage.getItem(VIEW_KEY);
    if (v === "bar" || v === "pie") setView(v);
    setCollapsed(window.localStorage.getItem(COLLAPSED_KEY) === "1");
    const p = window.localStorage.getItem(PERIOD_KEY);
    if (p && PERIODS.some((x) => x.value === p)) setPeriod(p as PeriodKey);
    setLive(window.localStorage.getItem(LIVE_KEY) === "1");
  }, []);

  const setViewPersisted = (v: "bar" | "pie") => {
    setView(v);
    if (typeof window !== "undefined") window.localStorage.setItem(VIEW_KEY, v);
  };

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

  const setLivePersisted = (l: boolean) => {
    setLive(l);
    if (typeof window !== "undefined") {
      window.localStorage.setItem(LIVE_KEY, l ? "1" : "0");
    }
  };

  if (facets.isLoading) {
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
  // Authoritative total from backend SELECT COUNT(*); no more summing
  // severities (which excludes unrated rows) or sources (which would
  // double-count multi-source CVEs after PR 10-AF).
  const total = data.total ?? 0;

  const sevByValue = new Map(data.severities?.map((b) => [b.value, b.count]) ?? []);
  const sevSlices: Slice[] = SEV_ORDER.map((k) => ({
    label: SEV_LABEL[k],
    count: sevByValue.get(k) ?? 0,
    color: SEV_HEX[k],
    href: { pathname: "/", query: { severity: k } },
  })).filter((s) => s.count > 0);

  const sourceSlices = buildSlices(
    topN(data.sources, 6),
    (v) => SOURCE_HEX[v] ?? "#94a3b8",
    undefined,
    (v) => SOURCE_LABEL[v] ?? v,
  );

  const typeSlices = buildSlices(
    topN(data.types, 8),
    (_v, i) => PIE_PALETTE[i % PIE_PALETTE.length],
    (v) => ({ pathname: "/", query: { type: v } }),
  );

  const domainSlices = buildSlices(
    topN(data.domains, 8),
    (_v, i) => PIE_PALETTE[(i + 3) % PIE_PALETTE.length],
    (v) => ({ pathname: "/", query: { domain: v } }),
  );

  const dayLo = formatDay(data.earliestPublishedAt);
  const dayHi = formatDay(data.latestPublishedAt);

  const groups: { title: string; slices: Slice[]; barTintMap?: Record<string, string>; barTextMap?: Record<string, string> }[] = [
    {
      title: "심각도",
      slices: sevSlices,
      barTintMap: SEV_BAR_TINT,
      barTextMap: SEV_TEXT,
    },
    {
      title: "출처",
      slices: sourceSlices,
      barTintMap: SOURCE_TINT,
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
          {/* Live polling toggle */}
          <button
            type="button"
            onClick={() => setLivePersisted(!live)}
            className={cn(
              "inline-flex h-7 items-center gap-1 rounded-full border px-2.5 text-[11px] transition-colors active:scale-95",
              live
                ? "border-emerald-500 bg-emerald-50 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-200"
                : "border-neutral-300 text-neutral-600 hover:bg-neutral-100 hover:text-neutral-900 dark:border-neutral-800 dark:text-neutral-400 dark:hover:bg-surface-2 dark:hover:text-neutral-100",
            )}
            aria-pressed={live}
            title={live ? "실시간 업데이트 끄기 (30초 폴링)" : "실시간 업데이트 켜기"}
          >
            {live ? <Pause className="h-3 w-3" /> : <Play className="h-3 w-3" />}
            {live ? "라이브" : "정지"}
          </button>
          {facets.isFetching && (
            <Loader2 className="h-3.5 w-3.5 animate-spin text-sky-600 dark:text-sky-400" />
          )}
          {/* View toggle (bar / pie) */}
          <div
            role="group"
            aria-label="차트 보기 방식"
            className="inline-flex overflow-hidden rounded-full border border-neutral-300 bg-white dark:border-neutral-800 dark:bg-surface-2"
          >
            <button
              type="button"
              onClick={() => setViewPersisted("bar")}
              className={cn(
                "inline-flex items-center gap-1 px-3 py-1 text-[11px] transition-colors",
                view === "bar"
                  ? "bg-sky-100 font-medium text-sky-800 dark:bg-sky-500/20 dark:text-sky-200"
                  : "text-neutral-600 hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-surface-3 dark:hover:text-neutral-100",
              )}
              aria-pressed={view === "bar"}
            >
              <BarChart3 className="h-3 w-3" />
              막대
            </button>
            <button
              type="button"
              onClick={() => setViewPersisted("pie")}
              className={cn(
                "inline-flex items-center gap-1 px-3 py-1 text-[11px] transition-colors",
                view === "pie"
                  ? "bg-sky-100 font-medium text-sky-800 dark:bg-sky-500/20 dark:text-sky-200"
                  : "text-neutral-600 hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-surface-3 dark:hover:text-neutral-100",
              )}
              aria-pressed={view === "pie"}
            >
              <PieChart className="h-3 w-3" />
              원형
            </button>
          </div>
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
        <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          {groups.map((g) => (
            <Group key={g.title} title={g.title}>
              {g.slices.length === 0 ? (
                <p className="text-xs text-neutral-500 dark:text-neutral-600">집계 데이터 없음.</p>
              ) : view === "pie" ? (
                <PieGroup slices={g.slices} total={total} />
              ) : (
                <BarGroup
                  slices={g.slices}
                  total={total}
                  barTintMap={g.barTintMap}
                  barTextMap={g.barTextMap}
                />
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

function BarGroup({
  slices,
  total,
  barTintMap,
  barTextMap,
}: {
  slices: Slice[];
  total: number;
  barTintMap?: Record<string, string>;
  barTextMap?: Record<string, string>;
}) {
  return (
    <ul className="space-y-1.5">
      {slices.map((s) => {
        const pct = total > 0 ? Math.max(0.5, (s.count / total) * 100) : 0;
        const lookupKey = s.label.toLowerCase().replace(/^(critical|high|medium|low|mitre|nvd|ghsa|exploit-db).*$/, (m) => m);
        const tintCls =
          (barTintMap && Object.keys(barTintMap).find((k) => SEV_LABEL[k] === s.label || SOURCE_LABEL[k] === s.label) &&
            barTintMap[Object.keys(barTintMap).find((k) => SEV_LABEL[k] === s.label || SOURCE_LABEL[k] === s.label)!]) ||
          undefined;
        const textCls =
          (barTextMap && Object.keys(barTextMap).find((k) => SEV_LABEL[k] === s.label) &&
            barTextMap[Object.keys(barTextMap).find((k) => SEV_LABEL[k] === s.label)!]) ||
          undefined;
        void lookupKey;
        const inner = (
          <>
            <div className="flex items-baseline justify-between gap-2 text-[11px]">
              <span className={cn("truncate font-medium", textCls ?? "text-neutral-300")}>
                {s.label}
              </span>
              <span className="shrink-0 tabular-nums text-neutral-400">
                {formatNumber(s.count)}
                <span className="ml-1 text-neutral-600">({pct.toFixed(pct < 10 ? 1 : 0)}%)</span>
              </span>
            </div>
            <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-neutral-800/70">
              <div
                className={cn(
                  "h-full rounded-full transition-[width]",
                  tintCls ?? "",
                )}
                style={{
                  width: `${pct}%`,
                  // Fallback to slice color when no tint class matches
                  // (types / domains use palette colors, not tailwind tokens).
                  backgroundColor: tintCls ? undefined : s.color,
                }}
              />
            </div>
          </>
        );
        return (
          <li key={s.label}>
            {s.href ? (
              <Link
                href={s.href}
                className="block rounded-lg px-1 py-1 transition-colors hover:bg-sky-500/5"
                title={`${s.label} 필터 적용`}
              >
                {inner}
              </Link>
            ) : (
              <div className="px-1 py-1">{inner}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

// Local Slice type is structurally identical to the shared PieSlice — keep
// it as a re-export so existing callers in this file (BarGroup etc.) don't
// need to import from a separate module just to type their arguments.
export type { PieSlice as _PieSliceReexport };
