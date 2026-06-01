"use client";

// Compact "어디부터 고칠 것인가" widget — folds the previous
// PrioritySignals + WhatToFixFirst panels into a single card.
//
// Layout, top-to-bottom:
//   1. Header strip — 3 stat chips for CVSS / EPSS / KEV (always
//      visible, gives the at-a-glance number for each pillar).
//   2. Three tier blocks side-by-side (좌 KEV 등재 / 중 EPSS 상위+외부
//      접점 / 우 CVSS 중간+EPSS 높음). Each block shows its TOP 5 CVEs;
//      the block header (label + count) links to /cves?priority=<key>
//      for the full bucket, and each listed CVE links to its detail.
//      The lowest-urgency long-tail tier (CVSS 높음+EPSS 낮음) is
//      intentionally omitted from this "what to fix first" view.
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
    queryKey: ["dashboard", "priorities", 5],
    queryFn: () => api.getDashboardPriorities({ perBucket: 5 }),
    staleTime: 60_000,
    refetchInterval: 5 * 60_000,
  });

  const signals = insightsQ.data?.prioritySignals;
  const buckets = prioritiesQ.data?.buckets ?? [];

  const isLoading = insightsQ.isLoading || prioritiesQ.isLoading;
  const error = (insightsQ.error || prioritiesQ.error) as Error | null;

  // "지금 고칠 것" 3블럭 — 가장 긴급한 세 티어만. 최하위 long-tail
  // (cvss_high_epss_low) 은 일정 패치 대상이라 이 뷰에서 제외.
  const byKey = new Map(buckets.map((b) => [b.key, b]));
  const tierBlocks = (["kev", "epss_high", "cvss_mid_epss_high"] as const)
    .map((k) => byKey.get(k))
    .filter((b): b is DashboardPriorityBucket => b != null);

  return (
    <WidgetCard
      title="패치 우선순위"
      description="CVSS(이론) · EPSS(예측) · KEV(실측) 세 신호를 합쳐 본 조치 순서"
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

      {/* 3 tier blocks — 좌 KEV / 중 EPSS 상위+외부 접점 / 우 CVSS 중간+EPSS 높음 */}
      <div className="mt-4 grid items-stretch gap-3 lg:grid-cols-3">
        {tierBlocks.map((b) => (
          <TierBlock key={b.key} bucket={b} />
        ))}
      </div>
    </WidgetCard>
  );
}

function TierBlock({ bucket }: { bucket: DashboardPriorityBucket }) {
  const meta = TIER_META[bucket.key];
  const { Icon } = meta;
  const items = bucket.items.slice(0, 5);
  return (
    <div className="flex flex-col overflow-hidden rounded-lg border border-neutral-200 dark:border-neutral-800">
      {/* 블럭 헤더 — 누르면 해당 티어 전체를 취약점 조회에서 봄 */}
      <Link
        href={`/cves?priority=${bucket.key}` as Route}
        className="flex items-center gap-2 border-b border-neutral-200 bg-neutral-50 px-3 py-2 transition-colors hover:bg-neutral-100 dark:border-neutral-800 dark:bg-surface-2 dark:hover:bg-surface-3"
        title={`${bucket.label} ${bucket.count.toLocaleString("ko-KR")}건 전체 보기`}
      >
        <Icon className={cn("h-4 w-4 shrink-0", meta.tint)} />
        <span className="min-w-0 flex-1 truncate text-[12px] font-semibold text-neutral-900 dark:text-neutral-100">
          {bucket.label}
        </span>
        <span className="shrink-0 tabular-nums text-[12px] font-bold text-neutral-900 dark:text-neutral-100">
          {bucket.count.toLocaleString("ko-KR")}
          <span className="ml-0.5 text-[10px] font-normal text-neutral-500">건</span>
        </span>
        <ChevronRight className="h-3.5 w-3.5 shrink-0 text-neutral-400 dark:text-neutral-600" />
      </Link>

      {/* TOP 5 — 각 CVE 는 상세로 이동 */}
      {items.length === 0 ? (
        <p className="px-3 py-4 text-[11px] text-neutral-500 dark:text-neutral-500">
          해당 CVE 가 없습니다.
        </p>
      ) : (
        <ol className="flex-1 divide-y divide-neutral-100 dark:divide-neutral-800/60">
          {items.map((it, i) => (
            <li key={it.cveId}>
              <Link
                href={`/cves/${it.cveId}` as Route}
                className="flex items-start gap-2 px-3 py-2 transition-colors hover:bg-neutral-50 dark:hover:bg-surface-2"
              >
                <span
                  className={cn(
                    "mt-0.5 inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full text-[9px] font-bold tabular-nums text-white",
                    meta.barTint,
                  )}
                >
                  {i + 1}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline justify-between gap-1.5">
                    <span className="truncate font-mono text-[11px] font-semibold text-neutral-900 dark:text-neutral-100">
                      {it.cveId}
                    </span>
                    {it.cvssScore != null && (
                      <span className="shrink-0 tabular-nums text-[10px] text-neutral-500 dark:text-neutral-500">
                        CVSS {it.cvssScore.toFixed(1)}
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 line-clamp-2 text-[10px] leading-snug text-neutral-600 dark:text-neutral-400">
                    {it.title}
                  </p>
                </div>
              </Link>
            </li>
          ))}
        </ol>
      )}
    </div>
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
