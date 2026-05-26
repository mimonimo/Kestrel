"use client";

// High-resolution CVSS score distribution. 10 fixed-width bins
// (0-1, 1-2, …, 9-10) so the long tail is visible, with severity-band
// coloring overlaid so the reader still recognizes the standard
// Low/Medium/High/Critical groupings at a glance. Inline mean/median/p90
// markers explain "where the typical score sits" without needing a
// second chart.

import Link from "next/link";
import type { Route } from "next";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { WidgetCard } from "./WidgetCard";
import { api, type DashboardCvssDistribution } from "@/lib/api";
import { cn } from "@/lib/utils";

// Severity band coloring per bin index (1..10). Matches the standard
// CVSS v3 buckets so a bin's color tells the user which severity it
// rolls up into.
function binTint(loInt: number): { fill: string; severity: "low" | "medium" | "high" | "critical" } {
  if (loInt >= 9) return { fill: "#f43f5e", severity: "critical" };
  if (loInt >= 7) return { fill: "#fb923c", severity: "high" };
  if (loInt >= 4) return { fill: "#fbbf24", severity: "medium" };
  return { fill: "#34d399", severity: "low" };
}

function severityHref(severity: "low" | "medium" | "high" | "critical"): Route {
  return `/cves?severity=${severity}` as Route;
}

export function CvssBucketsPanel() {
  const q = useQuery({
    queryKey: ["dashboard", "insights", "cvss"],
    queryFn: () => api.getDashboardInsights(),
    staleTime: 60_000,
    refetchInterval: 5 * 60_000,
  });

  const dist: DashboardCvssDistribution | undefined = q.data?.cvssDistribution;

  return (
    <WidgetCard
      title="CVSS 점수 분포"
      description="0–10 점을 10개 구간으로. 막대 클릭 시 해당 심각도 검색으로 이동"
      isLoading={q.isLoading}
      error={q.error as Error | null}
    >
      {!dist || dist.total === 0 ? (
        <p className="text-xs text-neutral-600 dark:text-neutral-500">
          점수가 채워진 CVE 가 아직 없습니다.
        </p>
      ) : (
        <>
          <Histogram dist={dist} />
          <StatRow dist={dist} />
        </>
      )}
    </WidgetCard>
  );
}

function Histogram({ dist }: { dist: DashboardCvssDistribution }) {
  const [hover, setHover] = useState<number | null>(null);
  const max = dist.histogram.reduce((m, b) => Math.max(m, b.count), 0);
  const VIEW_W = 600;
  const VIEW_H = 180;
  const PAD_L = 28;
  const PAD_R = 8;
  const PAD_T = 14;
  const PAD_B = 26;
  const innerW = VIEW_W - PAD_L - PAD_R;
  const innerH = VIEW_H - PAD_T - PAD_B;
  const barW = innerW / dist.histogram.length;

  const yFor = (count: number) => {
    if (max === 0) return VIEW_H - PAD_B;
    return VIEW_H - PAD_B - (count / max) * innerH;
  };
  const xForScore = (score: number) => PAD_L + (score / 10) * innerW;

  // Y-axis ticks: 0, mid, max
  const ticks = [0, Math.round(max / 2), max];

  return (
    <div className="relative w-full" onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${VIEW_W} ${VIEW_H}`} className="w-full" preserveAspectRatio="none" role="img" aria-label="CVSS 점수 히스토그램">
        {/* Grid lines */}
        {ticks.map((t, i) => {
          const y = yFor(t);
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
                {t.toLocaleString("ko-KR")}
              </text>
            </g>
          );
        })}

        {/* Bars */}
        {dist.histogram.map((b, i) => {
          const x = PAD_L + barW * i;
          const y = yFor(b.count);
          const h = VIEW_H - PAD_B - y;
          const tint = binTint(Math.floor(b.lo));
          const isHover = hover === i;
          return (
            <Link key={i} href={severityHref(tint.severity)}>
              <g
                onMouseEnter={() => setHover(i)}
                style={{ cursor: "pointer" }}
              >
                <rect
                  x={x + 1}
                  y={y}
                  width={Math.max(barW - 2, 1)}
                  height={Math.max(h, 1)}
                  rx={1.5}
                  fill={tint.fill}
                  fillOpacity={hover === null || isHover ? 0.95 : 0.45}
                  style={{ transition: "fill-opacity 120ms" }}
                />
                {/* Larger transparent hit area for hover/click */}
                <rect
                  x={x}
                  y={PAD_T}
                  width={barW}
                  height={VIEW_H - PAD_T - PAD_B}
                  fill="transparent"
                />
              </g>
            </Link>
          );
        })}

        {/* X-axis labels — every other tick to avoid overlap */}
        {Array.from({ length: 11 }, (_, i) => i).map((score) => {
          if (score % 2 !== 0 && score !== 10) return null;
          const x = xForScore(score);
          return (
            <text
              key={score}
              x={x}
              y={VIEW_H - 12}
              textAnchor="middle"
              className="fill-neutral-500 dark:fill-neutral-500"
              style={{ fontSize: 9 }}
            >
              {score}
            </text>
          );
        })}

        {/* Mean / median / p90 markers (선만 그림 — 라벨은 StatRow) */}
        {dist.median != null && (
          <Marker x={xForScore(dist.median)} y0={PAD_T} y1={VIEW_H - PAD_B} tint="text-sky-700 dark:text-sky-300" />
        )}
        {dist.mean != null && (
          <Marker x={xForScore(dist.mean)} y0={PAD_T} y1={VIEW_H - PAD_B} tint="text-violet-700 dark:text-violet-300" dashed />
        )}
        {dist.p90 != null && (
          <Marker x={xForScore(dist.p90)} y0={PAD_T} y1={VIEW_H - PAD_B} tint="text-rose-700 dark:text-rose-300" dotted />
        )}
      </svg>

      {hover != null && dist.histogram[hover] && (
        <div
          className="pointer-events-none absolute top-1 z-10 rounded-md border border-neutral-200 bg-white px-2 py-1 text-[11px] shadow-lg dark:border-neutral-700 dark:bg-surface-2"
          style={{
            left: `${((PAD_L + barW * hover + barW / 2) / VIEW_W) * 100}%`,
            transform: "translateX(-50%)",
            minWidth: 110,
          }}
        >
          <div className="font-semibold text-neutral-900 dark:text-neutral-100">
            CVSS {dist.histogram[hover].lo.toFixed(1)}–{dist.histogram[hover].hi.toFixed(1)}
          </div>
          <div className="tabular-nums text-neutral-700 dark:text-neutral-300">
            {dist.histogram[hover].count.toLocaleString("ko-KR")}건
          </div>
        </div>
      )}
    </div>
  );
}

function Marker({
  x,
  y0,
  y1,
  tint,
  dashed,
  dotted,
}: {
  x: number;
  y0: number;
  y1: number;
  tint: string;
  dashed?: boolean;
  dotted?: boolean;
}) {
  // 차트 안에는 세로선만. 평균/중앙값/p90 이 가까이 붙어 있을 때
  // 라벨이 서로 겹치던 문제를 차트 하단 StatRow 의 컬러 값으로 분리.
  const dash = dashed ? "4 3" : dotted ? "1 2" : undefined;
  return (
    <g className={tint}>
      <line
        x1={x}
        x2={x}
        y1={y0}
        y2={y1}
        stroke="currentColor"
        strokeWidth={1.2}
        strokeDasharray={dash}
        opacity={0.7}
      />
    </g>
  );
}

function StatRow({ dist }: { dist: DashboardCvssDistribution }) {
  return (
    <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-[11px]">
      <Stat label="총 점수 있음" value={dist.total.toLocaleString("ko-KR")} />
      <Stat
        label="평균"
        value={dist.mean != null ? dist.mean.toFixed(1) : "—"}
        tint="text-violet-700 dark:text-violet-300"
      />
      <Stat
        label="중앙값"
        value={dist.median != null ? dist.median.toFixed(1) : "—"}
        tint="text-sky-700 dark:text-sky-300"
      />
      <Stat
        label="상위 10%"
        value={dist.p90 != null ? dist.p90.toFixed(1) : "—"}
        tint="text-rose-700 dark:text-rose-300"
      />
      {dist.unscored > 0 && (
        <Stat
          label="점수 미상"
          value={dist.unscored.toLocaleString("ko-KR")}
          tint="text-neutral-500 dark:text-neutral-500"
        />
      )}
    </div>
  );
}

function Stat({ label, value, tint }: { label: string; value: string; tint?: string }) {
  return (
    <div className="flex items-baseline gap-1.5">
      <span className="text-[10px] uppercase tracking-wider text-neutral-500 dark:text-neutral-500">
        {label}
      </span>
      <span className={cn("tabular-nums text-sm font-semibold text-neutral-900 dark:text-neutral-100", tint)}>
        {value}
      </span>
    </div>
  );
}
