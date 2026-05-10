"use client";

import Link from "next/link";
import type { UrlObject } from "url";
import {
  BarChart3,
  ChevronDown,
  ChevronUp,
  Loader2,
  PieChart,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { api, type FacetBucket } from "@/lib/api";
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
  critical: "text-rose-300",
  high: "text-orange-300",
  medium: "text-amber-300",
  low: "text-emerald-300",
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

// Cycle of distinct colors for non-canonical groups (types / domains).
const PIE_PALETTE = [
  "#f472b6", "#a78bfa", "#38bdf8", "#34d399",
  "#fbbf24", "#fb923c", "#f43f5e", "#22d3ee",
];

const VIEW_KEY = "kestrel:vuln-dist:view"; // 'bar' | 'pie'
const COLLAPSED_KEY = "kestrel:vuln-dist:collapsed"; // '1' | '0'

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
  const facets = useQuery({
    queryKey: ["search", "facets"],
    queryFn: () => api.getSearchFacets(),
    staleTime: 60_000,
  });

  const [view, setView] = useState<"bar" | "pie">("bar");
  const [collapsed, setCollapsed] = useState(false);

  // Hydrate from localStorage so the user's chosen view + collapse state
  // sticks across page loads.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const v = window.localStorage.getItem(VIEW_KEY);
    if (v === "bar" || v === "pie") setView(v);
    setCollapsed(window.localStorage.getItem(COLLAPSED_KEY) === "1");
  }, []);

  const setViewPersisted = (v: "bar" | "pie") => {
    setView(v);
    if (typeof window !== "undefined") {
      window.localStorage.setItem(VIEW_KEY, v);
    }
  };

  const setCollapsedPersisted = (c: boolean) => {
    setCollapsed(c);
    if (typeof window !== "undefined") {
      window.localStorage.setItem(COLLAPSED_KEY, c ? "1" : "0");
    }
  };

  if (facets.isLoading) {
    return (
      <section className="mb-8 rounded-xl border border-sky-500/20 bg-gradient-to-br from-sky-500/5 to-transparent p-5">
        <div className="flex items-center gap-2 text-sm text-neutral-500">
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
    <section className="mb-8 rounded-xl border border-sky-500/20 bg-gradient-to-br from-sky-500/5 to-transparent p-5">
      <header className="mb-4 flex flex-wrap items-baseline justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-500/15 ring-1 ring-sky-400/30">
            <BarChart3 className="h-4 w-4 text-sky-300" />
          </div>
          <h2 className="text-base font-semibold text-neutral-100">
            수집된 취약점 분포
          </h2>
          <span className="rounded-full bg-sky-500/10 px-2 py-0.5 text-xs font-medium text-sky-200">
            총 {formatNumber(total)}건
          </span>
          {dayLo && dayHi && (
            <span className="text-xs text-neutral-500">
              {dayLo} ~ {dayHi}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1.5">
          {/* View toggle (bar / pie) */}
          <div
            role="group"
            aria-label="차트 보기 방식"
            className="inline-flex overflow-hidden rounded-md border border-neutral-800 bg-surface-2"
          >
            <button
              type="button"
              onClick={() => setViewPersisted("bar")}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-1 text-[11px] transition-colors",
                view === "bar"
                  ? "bg-sky-500/15 text-sky-200"
                  : "text-neutral-400 hover:text-neutral-100",
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
                "inline-flex items-center gap-1 border-l border-neutral-800 px-2 py-1 text-[11px] transition-colors",
                view === "pie"
                  ? "bg-sky-500/15 text-sky-200"
                  : "text-neutral-400 hover:text-neutral-100",
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
            className="inline-flex items-center gap-1 rounded-md border border-neutral-800 bg-surface-2 px-2 py-1 text-[11px] text-neutral-400 hover:text-neutral-100"
            aria-expanded={!collapsed}
          >
            {collapsed ? (
              <>
                <ChevronDown className="h-3 w-3" /> 펼치기
              </>
            ) : (
              <>
                <ChevronUp className="h-3 w-3" /> 숨기기
              </>
            )}
          </button>
        </div>
      </header>

      {!collapsed && (
        <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          {groups.map((g) => (
            <Group key={g.title} title={g.title}>
              {g.slices.length === 0 ? (
                <p className="text-xs text-neutral-500">집계 데이터 없음.</p>
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
      <h3 className="text-[11px] font-semibold uppercase tracking-wider text-neutral-500">
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
                className="block rounded-md px-1 py-1 transition-colors hover:bg-sky-500/5"
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

function PieGroup({ slices, total }: { slices: Slice[]; total: number }) {
  const groupTotal = slices.reduce((s, x) => s + x.count, 0);
  const ringDenom = groupTotal || 1;
  return (
    <div className="flex flex-col items-center gap-3 sm:flex-row sm:items-start sm:gap-4">
      <SvgPie slices={slices} total={ringDenom} />
      <ul className="min-w-0 flex-1 space-y-1 text-[11px]">
        {slices.map((s) => {
          const groupPct = (s.count / ringDenom) * 100;
          const corpusPct = total > 0 ? (s.count / total) * 100 : 0;
          const inner = (
            <div className="flex items-baseline justify-between gap-2">
              <span className="flex min-w-0 items-center gap-1.5">
                <span
                  className="inline-block h-2.5 w-2.5 shrink-0 rounded-sm"
                  style={{ backgroundColor: s.color }}
                />
                <span className="truncate text-neutral-300">{s.label}</span>
              </span>
              <span className="shrink-0 tabular-nums text-neutral-400">
                {formatNumber(s.count)}
                <span
                  className="ml-1 text-neutral-600"
                  title={`그룹 내 ${groupPct.toFixed(1)}% · 전체 ${corpusPct.toFixed(2)}%`}
                >
                  ({groupPct.toFixed(0)}%)
                </span>
              </span>
            </div>
          );
          return (
            <li key={s.label}>
              {s.href ? (
                <Link
                  href={s.href}
                  className="block rounded px-1 py-0.5 transition-colors hover:bg-sky-500/5"
                  title={`${s.label} 필터 적용`}
                >
                  {inner}
                </Link>
              ) : (
                <div className="px-1 py-0.5">{inner}</div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

// Inline SVG donut — no external chart lib. Each slice is a stroke-dash
// segment along a circle, ordered head-to-tail. Cap the donut at 100px
// so it fits in a 4-column grid even on narrow widths.
function SvgPie({ slices, total }: { slices: Slice[]; total: number }) {
  const size = 96;
  const r = 36;
  const cx = size / 2;
  const cy = size / 2;
  const circumference = 2 * Math.PI * r;
  let acc = 0;
  return (
    <svg
      viewBox={`0 0 ${size} ${size}`}
      width={size}
      height={size}
      role="img"
      aria-label="비율 차트"
      className="shrink-0 -rotate-90"
    >
      <circle
        cx={cx}
        cy={cy}
        r={r}
        fill="none"
        stroke="rgb(38 38 38 / 0.6)"
        strokeWidth={14}
      />
      {slices.map((s) => {
        const frac = total > 0 ? s.count / total : 0;
        const len = circumference * frac;
        const dasharray = `${len} ${circumference}`;
        const dashoffset = -circumference * (acc / total);
        acc += s.count;
        return (
          <circle
            key={s.label}
            cx={cx}
            cy={cy}
            r={r}
            fill="none"
            stroke={s.color}
            strokeWidth={14}
            strokeDasharray={dasharray}
            strokeDashoffset={dashoffset}
            strokeLinecap="butt"
          />
        );
      })}
    </svg>
  );
}
