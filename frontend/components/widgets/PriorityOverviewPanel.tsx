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
import { useState } from "react";
import {
  AlertOctagon,
  CalendarCheck,
  ChevronRight,
  Flame,
  TrendingUp,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";

import { WidgetCard } from "./WidgetCard";
import {
  api,
  type DashboardPriorityBucket,
} from "@/lib/api";
import { cn } from "@/lib/utils";

const TIER_META: Record<
  DashboardPriorityBucket["key"],
  { Icon: React.ComponentType<{ className?: string }>; tint: string; barTint: string; ringTint: string }
> = {
  kev: {
    Icon: Flame,
    tint: "text-rose-700 dark:text-rose-300",
    barTint: "bg-rose-500",
    ringTint: "ring-rose-400/60 dark:ring-rose-400/40",
  },
  epss_high: {
    Icon: TrendingUp,
    tint: "text-amber-700 dark:text-amber-300",
    barTint: "bg-amber-500",
    ringTint: "ring-amber-400/60 dark:ring-amber-400/40",
  },
  cvss_mid_epss_high: {
    Icon: AlertOctagon,
    tint: "text-violet-700 dark:text-violet-300",
    barTint: "bg-violet-500",
    ringTint: "ring-violet-400/60 dark:ring-violet-400/40",
  },
  cvss_high_epss_low: {
    Icon: CalendarCheck,
    tint: "text-sky-700 dark:text-sky-300",
    barTint: "bg-sky-500",
    ringTint: "ring-sky-400/60 dark:ring-sky-400/40",
  },
};

export function PriorityOverviewPanel({ className }: { className?: string }) {
  const prioritiesQ = useQuery({
    queryKey: ["dashboard", "priorities", 5],
    queryFn: () => api.getDashboardPriorities({ perBucket: 5 }),
    staleTime: 60_000,
    refetchInterval: 5 * 60_000,
  });

  const buckets = prioritiesQ.data?.buckets ?? [];

  const isLoading = prioritiesQ.isLoading;
  const error = prioritiesQ.error as Error | null;

  // 활성 티어 — 동그란 번호 버튼으로 전환. 기본은 첫(=가장 긴급) 티어.
  const [activeKey, setActiveKey] = useState<DashboardPriorityBucket["key"] | null>(null);
  const active = buckets.find((b) => b.key === activeKey) ?? buckets[0] ?? null;

  return (
    <WidgetCard
      title="패치 우선순위"
      description="CVSS(이론) · EPSS(예측) · KEV(실측) 세 신호를 합쳐 본 조치 순서"
      isLoading={isLoading}
      error={error}
      className={className}
    >
      {/* 순위 탭 — 동그란 색상 번호 버튼. 누르면 아래에 해당 순위 설명 + TOP 5. */}
      <div className="flex flex-wrap items-center gap-2">
        {buckets.map((b, idx) => {
          const meta = TIER_META[b.key];
          const isActive = active?.key === b.key;
          return (
            <button
              key={b.key}
              type="button"
              onClick={() => setActiveKey(b.key)}
              title={`${idx + 1}순위 · ${b.label}`}
              aria-pressed={isActive}
              aria-label={`${idx + 1}순위 ${b.label}`}
              className={cn(
                "inline-flex h-8 w-8 items-center justify-center rounded-full text-[13px] font-bold tabular-nums transition-all",
                isActive
                  ? cn(meta.barTint, "text-white shadow-sm ring-2 ring-offset-2 ring-offset-white dark:ring-offset-surface-1", meta.ringTint)
                  : "bg-neutral-200 text-neutral-500 hover:bg-neutral-300 hover:text-neutral-700 dark:bg-surface-2 dark:text-neutral-400 dark:hover:bg-surface-3 dark:hover:text-neutral-200",
              )}
            >
              {idx + 1}
            </button>
          );
        })}
      </div>

      {/* 활성 순위 상세 */}
      {active && <TierDetail bucket={active} />}
    </WidgetCard>
  );
}

function TierDetail({ bucket }: { bucket: DashboardPriorityBucket }) {
  const meta = TIER_META[bucket.key];
  const { Icon } = meta;
  const items = bucket.items.slice(0, 5);
  return (
    <div className="mt-3 overflow-hidden rounded-lg border border-neutral-200 dark:border-neutral-800">
      {/* 헤더 — 누르면 해당 순위 전체를 취약점 조회에서 봄 */}
      <Link
        href={`/cves?priority=${bucket.key}` as Route}
        className="flex items-center gap-2 border-b border-neutral-200 bg-neutral-50 px-3 py-2 transition-colors hover:bg-neutral-100 dark:border-neutral-800 dark:bg-surface-2 dark:hover:bg-surface-3"
        title={`${bucket.label} ${bucket.count.toLocaleString("ko-KR")}건 전체 보기`}
      >
        <Icon className={cn("h-4 w-4 shrink-0", meta.tint)} />
        <span className="min-w-0 flex-1 truncate text-[13px] font-semibold text-neutral-900 dark:text-neutral-100">
          {bucket.label}
        </span>
        <span className="shrink-0 tabular-nums text-[12px] font-bold text-neutral-900 dark:text-neutral-100">
          {bucket.count.toLocaleString("ko-KR")}
          <span className="ml-0.5 text-[10px] font-normal text-neutral-500">건</span>
        </span>
        <ChevronRight className="h-3.5 w-3.5 shrink-0 text-neutral-400 dark:text-neutral-600" />
      </Link>

      {/* 설명 */}
      {bucket.rationale && (
        <p className="border-b border-neutral-100 px-3 py-2 text-[11px] leading-relaxed text-neutral-600 dark:border-neutral-800/60 dark:text-neutral-400">
          {bucket.rationale}
        </p>
      )}

      {/* TOP 5 — 각 CVE 는 상세로 이동 */}
      {items.length === 0 ? (
        <p className="px-3 py-4 text-[11px] text-neutral-500 dark:text-neutral-500">
          해당 CVE 가 없습니다.
        </p>
      ) : (
        <ol className="divide-y divide-neutral-100 dark:divide-neutral-800/60">
          {items.map((it, i) => (
            <li key={it.cveId}>
              <Link
                href={`/cve/${it.cveId}` as Route}
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
