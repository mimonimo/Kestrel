"use client";

// Compact "어디부터 고칠 것인가" widget — folds the previous
// PrioritySignals + WhatToFixFirst panels into a single card.
//
// Layout, top-to-bottom:
//   1. Header strip — 3 stat chips for CVSS / EPSS / KEV (always
//      visible, gives the at-a-glance number for each pillar).
//   2. Ranked tier list — KEV → EPSS 상위 → CVSS 중간+EPSS 높음 →
//      CVSS 높음+EPSS 낮음. One row per tier with count + the most
//      recent example. Click a row to navigate into the CVE matching
//      that tier (the first row's top item).
//
// The reference deck the user pointed at is just the conceptual frame
// (CVSS theory / EPSS prediction / KEV observation). We don't try to
// match its visual layout 1:1.

import Link from "next/link";
import type { Route } from "next";
import {
  AlertOctagon,
  CalendarCheck,
  ChevronRight,
  Flame,
  Gauge,
  TrendingUp,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";

import { WidgetCard } from "./WidgetCard";
import {
  api,
  type DashboardPriorityBucket,
} from "@/lib/api";
import { cn } from "@/lib/utils";

const PILLAR_META = {
  cvss: {
    label: "CVSS",
    sub: "이론",
    Icon: Gauge,
    tint: "text-sky-700 dark:text-sky-300",
    bg: "bg-sky-50 dark:bg-sky-500/10",
  },
  epss: {
    label: "EPSS",
    sub: "예측",
    Icon: TrendingUp,
    tint: "text-amber-700 dark:text-amber-300",
    bg: "bg-amber-50 dark:bg-amber-500/10",
  },
  kev: {
    label: "KEV",
    sub: "실측",
    Icon: AlertOctagon,
    tint: "text-rose-700 dark:text-rose-300",
    bg: "bg-rose-50 dark:bg-rose-500/10",
  },
} as const;

const TIER_META: Record<
  DashboardPriorityBucket["key"],
  { Icon: React.ComponentType<{ className?: string }>; tint: string; barTint: string }
> = {
  kev: {
    Icon: Flame,
    tint: "text-rose-700 dark:text-rose-300",
    barTint: "bg-rose-500",
  },
  epss_high: {
    Icon: TrendingUp,
    tint: "text-amber-700 dark:text-amber-300",
    barTint: "bg-amber-500",
  },
  cvss_mid_epss_high: {
    Icon: AlertOctagon,
    tint: "text-violet-700 dark:text-violet-300",
    barTint: "bg-violet-500",
  },
  cvss_high_epss_low: {
    Icon: CalendarCheck,
    tint: "text-sky-700 dark:text-sky-300",
    barTint: "bg-sky-500",
  },
};

export function PriorityOverviewPanel() {
  const insightsQ = useQuery({
    queryKey: ["dashboard", "insights", "priority-signals"],
    queryFn: () => api.getDashboardInsights(),
    staleTime: 60_000,
    refetchInterval: 60_000,
  });
  const prioritiesQ = useQuery({
    queryKey: ["dashboard", "priorities", 1],
    queryFn: () => api.getDashboardPriorities({ perBucket: 1 }),
    staleTime: 60_000,
    refetchInterval: 5 * 60_000,
  });

  const signals = insightsQ.data?.prioritySignals;
  const buckets = prioritiesQ.data?.buckets ?? [];

  const isLoading = insightsQ.isLoading || prioritiesQ.isLoading;
  const error = (insightsQ.error || prioritiesQ.error) as Error | null;

  // Total used to draw the proportion bar — relative to the biggest
  // bucket so a long tail (CVSS-only) doesn't crush the urgent rows.
  const maxCount = buckets.reduce((m, b) => Math.max(m, b.count), 0);

  return (
    <WidgetCard
      title="패치 우선순위"
      description="CVSS(이론) · EPSS(예측) · KEV(실측) 세 신호를 합쳐 본 조치 순서 — 행 클릭 시 해당 묶음 전체 보기"
      isLoading={isLoading}
      error={error}
    >
      {/* Pillar chips */}
      <div className="grid gap-2 sm:grid-cols-3">
        <PillarChip
          pillar="cvss"
          primary={signals?.cvssCritical}
          primaryLabel="Critical 9.0+"
          secondary={signals?.cvssHigh}
          secondaryLabel="High 7.0+"
        />
        <PillarChip
          pillar="epss"
          primary={signals?.epssHigh}
          primaryLabel="≥ 0.5"
          secondary={signals?.epssTopPercentile}
          secondaryLabel="상위 5%"
        />
        <PillarChip
          pillar="kev"
          primary={signals?.kevListed}
          primaryLabel="현재 등재"
        />
      </div>

      {/* Ranked tiers */}
      <ol className="mt-4 space-y-1.5">
        {buckets.map((b, idx) => {
          const meta = TIER_META[b.key];
          const { Icon } = meta;
          const top = b.items[0];
          const pct = maxCount > 0 ? (b.count / maxCount) * 100 : 0;
          const rowInner = (
            <div className="flex items-center gap-3 px-2 py-2">
              <span
                className={cn(
                  "inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[11px] font-bold tabular-nums text-white shadow-sm",
                  meta.barTint,
                )}
              >
                {idx + 1}
              </span>
              <Icon className={cn("h-3.5 w-3.5 shrink-0", meta.tint)} />
              <div className="min-w-0 flex-1">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="truncate text-[12px] font-medium text-neutral-900 dark:text-neutral-100">
                    {b.label}
                  </span>
                  <span className="shrink-0 tabular-nums text-[12px] font-semibold text-neutral-900 dark:text-neutral-100">
                    {b.count.toLocaleString("ko-KR")}
                    <span className="ml-0.5 text-[10px] text-neutral-500">건</span>
                  </span>
                </div>
                <div className="mt-1 h-1 overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-800">
                  <div
                    className={cn("h-full rounded-full", meta.barTint)}
                    style={{ width: `${Math.max(pct, 1.5)}%` }}
                  />
                </div>
                {top && (
                  <div className="mt-1 flex items-baseline justify-between gap-2 text-[10px] text-neutral-600 dark:text-neutral-500">
                    <span className="flex min-w-0 items-baseline gap-1.5">
                      <span className="font-mono text-neutral-800 dark:text-neutral-300">
                        {top.cveId}
                      </span>
                      <span className="truncate">{top.title}</span>
                    </span>
                    {b.count > 1 && (
                      <span className="shrink-0">외 {(b.count - 1).toLocaleString("ko-KR")}건</span>
                    )}
                  </div>
                )}
              </div>
              <ChevronRight className="h-3.5 w-3.5 shrink-0 text-neutral-400 dark:text-neutral-600" />
            </div>
          );
          // Row click drills into /cves with the tier filter applied
          // so the user sees the *full* bucket, not just the top item.
          // The dashboard panel only ever shows the lead CVE; clicking
          // a row was previously misleading because it routed to that
          // single CVE's detail page.
          return (
            <li key={b.key}>
              <Link
                href={`/cves?priority=${b.key}` as Route}
                className="block rounded-lg transition-colors hover:bg-neutral-50 dark:hover:bg-surface-2"
                title={`${b.label} ${b.count.toLocaleString("ko-KR")}건 전체 보기`}
              >
                {rowInner}
              </Link>
            </li>
          );
        })}
      </ol>
    </WidgetCard>
  );
}

interface PillarChipProps {
  pillar: keyof typeof PILLAR_META;
  primary?: number;
  primaryLabel: string;
  secondary?: number;
  secondaryLabel?: string;
}

function PillarChip({
  pillar,
  primary,
  primaryLabel,
  secondary,
  secondaryLabel,
}: PillarChipProps) {
  const meta = PILLAR_META[pillar];
  const { Icon } = meta;
  return (
    <div className={cn("rounded-lg px-3 py-2", meta.bg)}>
      <div className="flex items-center justify-between gap-2">
        <div className={cn("flex items-center gap-1.5 text-[11px] font-semibold", meta.tint)}>
          <Icon className="h-3.5 w-3.5" />
          {meta.label}
        </div>
        <span className={cn("text-[9px] font-medium uppercase tracking-wider", meta.tint)}>
          {meta.sub}
        </span>
      </div>
      <div className="mt-1 flex items-baseline justify-between gap-2">
        <span className="text-[10px] text-neutral-600 dark:text-neutral-400">
          {primaryLabel}
        </span>
        <span className="tabular-nums text-base font-bold text-neutral-900 dark:text-neutral-100">
          {primary == null ? "—" : primary.toLocaleString("ko-KR")}
        </span>
      </div>
      {secondaryLabel && (
        <div className="mt-0.5 flex items-baseline justify-between gap-2">
          <span className="text-[10px] text-neutral-600 dark:text-neutral-400">
            {secondaryLabel}
          </span>
          <span className="tabular-nums text-[11px] font-semibold text-neutral-700 dark:text-neutral-300">
            {secondary == null ? "—" : secondary.toLocaleString("ko-KR")}
          </span>
        </div>
      )}
    </div>
  );
}
