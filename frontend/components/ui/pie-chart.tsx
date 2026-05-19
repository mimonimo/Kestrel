"use client";

import type { UrlObject } from "url";
import Link from "next/link";

import { cn } from "@/lib/utils";

export interface PieSlice {
  label: string;
  count: number;
  color: string;
  href?: UrlObject;
}

function formatNumber(n: number): string {
  return n.toLocaleString("ko-KR");
}

// Inline SVG donut — no external chart lib. Each slice is a stroke-dash
// segment along a circle, ordered head-to-tail. ``size`` defaults to 96
// so it fits in a 4-column grid even on narrow widths; pass a smaller
// value for compact panels.
export function SvgPie({
  slices,
  total,
  size = 96,
}: {
  slices: PieSlice[];
  total: number;
  size?: number;
}) {
  const r = (size - 24) / 2; // ring thickness = 14, leave 12px padding total
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
        // Track tint — light mode soft grey, dark mode darker grey.
        className="stroke-neutral-200 dark:stroke-neutral-800"
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

export function PieGroup({
  slices,
  total,
  groupTotal: groupTotalOverride,
  size,
  emptyLabel = "데이터 없음",
  className,
}: {
  slices: PieSlice[];
  // Authoritative total over the whole corpus — drives the "전체 X%"
  // tooltip in addition to the group-relative ratio.
  total: number;
  // Optional explicit group total. Defaults to sum(slices). Useful when
  // the panel wants the ring to represent a subset of the corpus.
  groupTotal?: number;
  size?: number;
  emptyLabel?: string;
  className?: string;
}) {
  const groupTotal = groupTotalOverride ?? slices.reduce((s, x) => s + x.count, 0);
  const ringDenom = groupTotal || 1;
  if (slices.length === 0 || groupTotal === 0) {
    return <p className={cn("text-xs text-neutral-600 dark:text-neutral-500", className)}>{emptyLabel}</p>;
  }
  return (
    <div className={cn("flex flex-col items-center gap-3 sm:flex-row sm:items-start sm:gap-4", className)}>
      <SvgPie slices={slices} total={ringDenom} size={size} />
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
                <span className="truncate text-neutral-800 dark:text-neutral-300">{s.label}</span>
              </span>
              <span className="shrink-0 tabular-nums text-neutral-700 dark:text-neutral-400">
                {formatNumber(s.count)}
                <span
                  className="ml-1 text-neutral-500 dark:text-neutral-600"
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

// Cycle of distinct colors for non-canonical groups (types / kinds /
// domains). Re-exported here so panels that need a palette don't have
// to duplicate it.
export const PIE_PALETTE = [
  "#f472b6", "#a78bfa", "#38bdf8", "#34d399",
  "#fbbf24", "#fb923c", "#f43f5e", "#22d3ee",
];
