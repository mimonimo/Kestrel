"use client";

import type { UrlObject } from "url";
import Link from "next/link";
import { useState } from "react";

import { cn } from "@/lib/utils";

export interface PieSlice {
  label: string;
  count: number;
  color: string;
  // Click navigates to this URL (CVE list filter). Mutually exclusive
  // with ``onClick`` — onClick wins when both are set.
  href?: UrlObject;
  // Click toggles a cross-filter selection in the parent component.
  // When this is set the slice/legend row become buttons instead of
  // links so screen-reader semantics stay correct.
  onClick?: () => void;
  // Highlight the slice as the currently active filter (raised + bold
  // legend). Other slices in the same group should set ``dimmed`` so
  // the active one visually dominates.
  selected?: boolean;
  // Greyed-out, non-active slice in a group where something else is
  // selected.
  dimmed?: boolean;
}

function formatNumber(n: number): string {
  return n.toLocaleString("ko-KR");
}

// Inline SVG donut — no external chart lib. Each slice is a stroke-dash
// segment along a circle, ordered head-to-tail. ``size`` defaults to 96
// so it fits in a 4-column grid even on narrow widths; pass a smaller
// value for compact panels.
//
// Interactivity: hover a slice → it pops out (translate radially) and
// gains a brighter glow; the matching legend row in PieGroup highlights
// at the same time via shared ``hoveredLabel`` state. Click forwards to
// ``href`` if set (filter application).
export function SvgPie({
  slices,
  total,
  size = 96,
  hoveredLabel,
  onHover,
}: {
  slices: PieSlice[];
  total: number;
  size?: number;
  hoveredLabel?: string | null;
  onHover?: (label: string | null) => void;
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
      className="shrink-0 -rotate-90 overflow-visible"
    >
      <circle
        cx={cx}
        cy={cy}
        r={r}
        fill="none"
        className="stroke-neutral-200 dark:stroke-neutral-800"
        strokeWidth={14}
      />
      {slices.map((s, i) => {
        const frac = total > 0 ? s.count / total : 0;
        const len = circumference * frac;
        const dasharray = `${len} ${circumference}`;
        const dashoffset = -circumference * (acc / total);
        // Compute the angle of the slice midpoint so we can offset it
        // radially when hovered (gives a "pop out" effect).
        const midAngle = (2 * Math.PI * (acc + s.count / 2)) / total;
        acc += s.count;
        const hovered = hoveredLabel === s.label;
        // Selected slices stay popped out + bright even without hover so
        // the active cross-filter is obvious; sibling slices in the same
        // group fade to 0.3 when dimmed by selection.
        const isInteractive = !!(s.onClick || s.href);
        const popped = hovered || !!s.selected;
        const isDimmed = (hoveredLabel != null && !hovered) || !!s.dimmed;
        const dx = popped ? Math.cos(midAngle) * 3 : 0;
        const dy = popped ? Math.sin(midAngle) * 3 : 0;
        return (
          <circle
            key={`${s.label}-${i}`}
            cx={cx}
            cy={cy}
            r={r}
            fill="none"
            stroke={s.color}
            strokeWidth={popped ? 16 : 14}
            strokeDasharray={dasharray}
            strokeDashoffset={dashoffset}
            strokeLinecap="butt"
            style={{
              transform: `translate(${dx}px, ${dy}px)`,
              opacity: isDimmed ? 0.3 : 1,
              transition: "transform 150ms ease, opacity 150ms ease, stroke-width 150ms ease",
              cursor: isInteractive ? "pointer" : undefined,
            }}
            onMouseEnter={() => onHover?.(s.label)}
            onMouseLeave={() => onHover?.(null)}
            onClick={s.onClick}
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
  const [hovered, setHovered] = useState<string | null>(null);
  const groupTotal = groupTotalOverride ?? slices.reduce((s, x) => s + x.count, 0);
  const ringDenom = groupTotal || 1;
  if (slices.length === 0 || groupTotal === 0) {
    return (
      <p className={cn("text-xs text-neutral-600 dark:text-neutral-500", className)}>
        {emptyLabel}
      </p>
    );
  }
  return (
    <div
      className={cn(
        "flex flex-col items-center gap-3 sm:flex-row sm:items-start sm:gap-4",
        className,
      )}
    >
      <SvgPie
        slices={slices}
        total={ringDenom}
        size={size}
        hoveredLabel={hovered}
        onHover={setHovered}
      />
      <ul className="min-w-0 flex-1 space-y-1 text-[11px]">
        {slices.map((s) => {
          const groupPct = (s.count / ringDenom) * 100;
          const corpusPct = total > 0 ? (s.count / total) * 100 : 0;
          const isHovered = hovered === s.label;
          // Two sources of "dimmed": cursor on a sibling, or another
          // slice in the group is selected as the active cross-filter.
          const isHoverDimmed = hovered != null && !isHovered;
          const isFilterDimmed = !!s.dimmed;
          const isDimmed = isHoverDimmed || isFilterDimmed;
          const isSelected = !!s.selected;
          const inner = (
            <div className="flex items-baseline justify-between gap-2">
              <span className="flex min-w-0 items-center gap-1.5">
                <span
                  className="inline-block h-2.5 w-2.5 shrink-0 rounded-sm transition-transform duration-150"
                  style={{
                    backgroundColor: s.color,
                    transform: isHovered || isSelected ? "scale(1.3)" : "scale(1)",
                  }}
                />
                <span
                  className={cn(
                    "truncate transition-colors",
                    isHovered || isSelected
                      ? "font-medium text-neutral-900 dark:text-neutral-100"
                      : "text-neutral-800 dark:text-neutral-300",
                  )}
                >
                  {s.label}
                </span>
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
          const rowCls = cn(
            "block w-full rounded px-1 py-0.5 text-left transition-all duration-150",
            isHoverDimmed && "opacity-50",
            isFilterDimmed && !isHoverDimmed && "opacity-40",
            isSelected &&
              "bg-sky-50 ring-1 ring-inset ring-sky-400/40 dark:bg-sky-500/10 dark:ring-sky-500/40",
            (s.href || s.onClick) &&
              !isSelected &&
              "hover:bg-sky-50 dark:hover:bg-sky-500/5",
          );
          return (
            <li
              key={s.label}
              onMouseEnter={() => setHovered(s.label)}
              onMouseLeave={() => setHovered(null)}
            >
              {s.onClick ? (
                <button
                  type="button"
                  onClick={s.onClick}
                  className={rowCls}
                  title={isSelected ? `${s.label} 필터 해제` : `${s.label} 필터 적용`}
                  aria-pressed={isSelected}
                >
                  {inner}
                </button>
              ) : s.href ? (
                <Link href={s.href} className={rowCls} title={`${s.label} 필터 적용`}>
                  {inner}
                </Link>
              ) : (
                <div className={rowCls}>{inner}</div>
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
