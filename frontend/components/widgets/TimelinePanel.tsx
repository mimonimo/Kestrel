"use client";

// Severity-stacked area chart of daily new CVE counts. Inline SVG (no
// external chart library) for the same reason the pie chart is inline:
// avoids a 50-100KB dependency for one shape, and keeps theming under
// our control. Hover shows a tooltip with the daily breakdown.

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { WidgetCard } from "./WidgetCard";
import { api, type DashboardTimelineDay } from "@/lib/api";
import { cn } from "@/lib/utils";

const RANGES = [
  { value: 7, label: "7일" },
  { value: 30, label: "30일" },
  { value: 90, label: "90일" },
] as const;

const SEV_COLORS = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#34d399",
} as const;

function formatDayShort(iso: string): string {
  const d = new Date(iso);
  return `${d.getMonth() + 1}/${d.getDate()}`;
}

export function TimelinePanel() {
  const [days, setDays] = useState<number>(30);

  const q = useQuery({
    queryKey: ["dashboard", "insights", "timeline", days],
    queryFn: () => api.getDashboardInsights({ days }),
    staleTime: 60_000,
    refetchInterval: 60_000,
  });

  const timeline: DashboardTimelineDay[] = q.data?.timeline ?? [];

  const stats = useMemo(() => {
    if (!timeline.length) {
      return { total: 0, peak: 0, peakDay: "", avg: 0 };
    }
    const total = timeline.reduce((s, d) => s + d.total, 0);
    let peak = 0;
    let peakDay = "";
    for (const d of timeline) {
      if (d.total > peak) {
        peak = d.total;
        peakDay = d.date;
      }
    }
    const avg = Math.round(total / timeline.length);
    return { total, peak, peakDay, avg };
  }, [timeline]);

  return (
    <WidgetCard
      title="신규 CVE 추이"
      description={`최근 ${days}일 일별 등록량 · 심각도별 누적`}
      isLoading={q.isLoading}
      error={q.error as Error | null}
      actions={
        <div
          role="group"
          aria-label="기간"
          className="inline-flex overflow-hidden rounded-full border border-neutral-300 bg-white text-[11px] dark:border-neutral-800 dark:bg-surface-2"
        >
          {RANGES.map((r) => (
            <button
              key={r.value}
              type="button"
              onClick={() => setDays(r.value)}
              className={cn(
                "px-2.5 py-1 transition-colors",
                days === r.value
                  ? "bg-sky-100 font-medium text-sky-800 dark:bg-sky-500/20 dark:text-sky-200"
                  : "text-neutral-600 hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-surface-3 dark:hover:text-neutral-100",
              )}
              aria-pressed={days === r.value}
            >
              {r.label}
            </button>
          ))}
        </div>
      }
    >
      {timeline.length === 0 ? (
        <p className="text-xs text-neutral-600 dark:text-neutral-500">
          이 기간에 수집된 CVE 가 없습니다.
        </p>
      ) : (
        <>
          <div className="mb-3 flex flex-wrap gap-4 text-[11px]">
            <Stat label="합계" value={stats.total.toLocaleString("ko-KR")} />
            <Stat label="일평균" value={stats.avg.toLocaleString("ko-KR")} />
            <Stat
              label="최다일"
              value={
                stats.peak
                  ? `${stats.peak.toLocaleString("ko-KR")} (${formatDayShort(stats.peakDay)})`
                  : "—"
              }
            />
          </div>
          <StackedArea data={timeline} />
          <Legend />
        </>
      )}
    </WidgetCard>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-neutral-500 dark:text-neutral-500">
        {label}
      </div>
      <div className="text-sm font-semibold tabular-nums text-neutral-900 dark:text-neutral-100">
        {value}
      </div>
    </div>
  );
}

function Legend() {
  return (
    <ul className="mt-3 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-neutral-600 dark:text-neutral-400">
      {(["critical", "high", "medium", "low"] as const).map((s) => (
        <li key={s} className="flex items-center gap-1.5">
          <span
            className="inline-block h-2 w-2 rounded-sm"
            style={{ backgroundColor: SEV_COLORS[s] }}
          />
          {s === "critical" ? "Critical" : s === "high" ? "High" : s === "medium" ? "Medium" : "Low"}
        </li>
      ))}
    </ul>
  );
}

const VIEW_W = 600;
const VIEW_H = 160;
const PAD_L = 28;
const PAD_R = 8;
const PAD_T = 8;
const PAD_B = 18;

function StackedArea({ data }: { data: DashboardTimelineDay[] }) {
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  const maxY = Math.max(1, ...data.map((d) => d.total));
  const stepX = (VIEW_W - PAD_L - PAD_R) / Math.max(1, data.length - 1);

  // Build cumulative stacks from bottom up: low → medium → high → critical
  const order: ("low" | "medium" | "high" | "critical")[] = ["low", "medium", "high", "critical"];

  function yForCumulative(value: number): number {
    const ratio = value / maxY;
    return VIEW_H - PAD_B - ratio * (VIEW_H - PAD_T - PAD_B);
  }

  // Pre-compute cumulative values per day
  const layers = order.map((sev, layerIdx) => {
    const points = data.map((d, i) => {
      const x = PAD_L + stepX * i;
      let cum = 0;
      for (let j = 0; j <= layerIdx; j++) {
        const k = order[j];
        cum += d[k];
      }
      return { x, y: yForCumulative(cum), value: cum };
    });
    return { sev, points };
  });

  // Build path strings (area = top line + bottom line reverse)
  function buildArea(layerIdx: number): string {
    const top = layers[layerIdx].points;
    // bottom is previous layer's top, or y=0 (chart bottom) for first layer
    const bottom =
      layerIdx === 0
        ? top.map((p) => ({ x: p.x, y: yForCumulative(0) }))
        : layers[layerIdx - 1].points;
    const topSeg = top.map((p, i) => `${i === 0 ? "M" : "L"}${p.x.toFixed(2)},${p.y.toFixed(2)}`).join(" ");
    const botSeg = [...bottom]
      .reverse()
      .map((p) => `L${p.x.toFixed(2)},${p.y.toFixed(2)}`)
      .join(" ");
    return `${topSeg} ${botSeg} Z`;
  }

  // Y-axis ticks — 0, mid, max
  const ticks = [0, Math.round(maxY / 2), maxY];

  return (
    <div
      className="relative w-full"
      onMouseLeave={() => setHoverIdx(null)}
    >
      <svg
        viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
        className="w-full"
        preserveAspectRatio="none"
        role="img"
        aria-label="신규 CVE 일별 추이 영역 차트"
      >
        {/* grid lines */}
        {ticks.map((t, i) => {
          const y = yForCumulative(t);
          return (
            <g key={i}>
              <line
                x1={PAD_L}
                x2={VIEW_W - PAD_R}
                y1={y}
                y2={y}
                stroke="currentColor"
                strokeWidth={0.5}
                className="text-neutral-200 dark:text-neutral-800"
              />
              <text
                x={PAD_L - 4}
                y={y + 3}
                textAnchor="end"
                className="fill-neutral-500 dark:fill-neutral-500"
                style={{ fontSize: 9 }}
              >
                {t}
              </text>
            </g>
          );
        })}

        {/* areas — paint from top of stack (critical) to bottom so each
            stays visible as the lower layers paint over (stacked area). */}
        {layers.map((layer, idx) => (
          <path
            key={layer.sev}
            d={buildArea(idx)}
            fill={SEV_COLORS[layer.sev]}
            fillOpacity={0.85}
            stroke={SEV_COLORS[layer.sev]}
            strokeWidth={0.6}
          />
        ))}

        {/* x-axis labels — sparse (~5 ticks) so they don't overlap. */}
        {data.map((d, i) => {
          const showEvery = Math.max(1, Math.floor(data.length / 6));
          if (i % showEvery !== 0 && i !== data.length - 1) return null;
          const x = PAD_L + stepX * i;
          return (
            <text
              key={d.date}
              x={x}
              y={VIEW_H - 4}
              textAnchor="middle"
              className="fill-neutral-500 dark:fill-neutral-500"
              style={{ fontSize: 9 }}
            >
              {formatDayShort(d.date)}
            </text>
          );
        })}

        {/* hover hit areas — invisible vertical bands, one per day */}
        {data.map((d, i) => {
          const x = PAD_L + stepX * i - stepX / 2;
          const w = stepX;
          return (
            <rect
              key={`hit-${d.date}`}
              x={x}
              y={PAD_T}
              width={w}
              height={VIEW_H - PAD_T - PAD_B}
              fill="transparent"
              onMouseEnter={() => setHoverIdx(i)}
              style={{ cursor: "crosshair" }}
            />
          );
        })}

        {/* hover vertical guide */}
        {hoverIdx != null && (
          <line
            x1={PAD_L + stepX * hoverIdx}
            x2={PAD_L + stepX * hoverIdx}
            y1={PAD_T}
            y2={VIEW_H - PAD_B}
            stroke="currentColor"
            strokeDasharray="2 2"
            strokeWidth={0.8}
            className="text-neutral-500 dark:text-neutral-400"
          />
        )}
      </svg>

      {/* Floating tooltip — positioned in DOM, easier than SVG foreignObject */}
      {hoverIdx != null && data[hoverIdx] && (
        <div
          className="pointer-events-none absolute top-1 z-10 rounded-md border border-neutral-200 bg-white px-2.5 py-1.5 text-[11px] shadow-lg shadow-black/10 dark:border-neutral-700 dark:bg-surface-2 dark:shadow-black/40"
          style={{
            left: `${((PAD_L + stepX * hoverIdx) / VIEW_W) * 100}%`,
            transform: "translateX(-50%)",
            minWidth: 130,
          }}
        >
          <div className="mb-1 font-semibold text-neutral-900 dark:text-neutral-100">
            {data[hoverIdx].date}
          </div>
          <TooltipRow label="Total" value={data[hoverIdx].total} />
          <TooltipRow label="Critical" value={data[hoverIdx].critical} color={SEV_COLORS.critical} />
          <TooltipRow label="High" value={data[hoverIdx].high} color={SEV_COLORS.high} />
          <TooltipRow label="Medium" value={data[hoverIdx].medium} color={SEV_COLORS.medium} />
          <TooltipRow label="Low" value={data[hoverIdx].low} color={SEV_COLORS.low} />
        </div>
      )}
    </div>
  );
}

function TooltipRow({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color?: string;
}) {
  return (
    <div className="flex items-center justify-between gap-3 text-neutral-700 dark:text-neutral-300">
      <span className="flex items-center gap-1.5">
        {color && (
          <span className="inline-block h-1.5 w-1.5 rounded-sm" style={{ backgroundColor: color }} />
        )}
        {label}
      </span>
      <span className="tabular-nums">{value.toLocaleString("ko-KR")}</span>
    </div>
  );
}
