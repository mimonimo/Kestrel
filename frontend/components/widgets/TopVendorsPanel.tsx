"use client";

// Top vendors by # of CVEs they're listed under. Horizontal bars so
// long vendor names fit, sorted desc. Clicking a row deep-links into
// /cves with a hint query so the user can immediately drill down.

import Link from "next/link";
import type { Route } from "next";
import { useQuery } from "@tanstack/react-query";

import { WidgetCard } from "./WidgetCard";
import { api, type DashboardVendorBucket } from "@/lib/api";

export function TopVendorsPanel() {
  const q = useQuery({
    queryKey: ["dashboard", "insights", "vendors"],
    queryFn: () => api.getDashboardInsights({ vendorLimit: 10 }),
    staleTime: 60_000,
    refetchInterval: 5 * 60_000,
  });

  const vendors: DashboardVendorBucket[] = q.data?.topVendors ?? [];
  const max = vendors.reduce((m, v) => Math.max(m, v.count), 0);

  return (
    <WidgetCard
      title="영향 벤더 Top 10"
      description="수집된 CVE 가 가장 많이 분포한 벤더 — 카드 클릭 시 해당 벤더 검색으로 이동"
      isLoading={q.isLoading}
      error={q.error as Error | null}
    >
      {vendors.length === 0 ? (
        <p className="text-xs text-neutral-600 dark:text-neutral-500">
          집계된 벤더가 없습니다.
        </p>
      ) : (
        <ul className="space-y-1.5">
          {vendors.map((v, i) => {
            const pct = max > 0 ? (v.count / max) * 100 : 0;
            return (
              <li key={v.vendor}>
                <Link
                  href={
                    // useUrlState reads the keyword query from `?q=`, not
                    // `?query=` — wrong key here meant the /cves page
                    // mounted with an empty search bar instead of the
                    // vendor name we pushed.
                    `/cves?q=${encodeURIComponent(v.vendor)}` as Route
                  }
                  className="block rounded-md px-1.5 py-1 hover:bg-sky-50 dark:hover:bg-sky-500/5"
                  title={`${v.vendor} CVE 보기`}
                >
                  <div className="mb-0.5 flex items-baseline justify-between gap-2 text-[11px]">
                    <span className="flex min-w-0 items-center gap-2 text-neutral-800 dark:text-neutral-200">
                      <span className="inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-sm bg-neutral-200 text-[9px] font-semibold tabular-nums text-neutral-700 dark:bg-neutral-800 dark:text-neutral-400">
                        {i + 1}
                      </span>
                      <span className="truncate" title={v.vendor}>
                        {v.vendor}
                      </span>
                    </span>
                    <span className="tabular-nums text-neutral-600 dark:text-neutral-400">
                      {v.count.toLocaleString("ko-KR")}
                    </span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-800">
                    <div
                      className="h-full rounded-full bg-sky-500 transition-[width] duration-300 dark:bg-sky-400"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </WidgetCard>
  );
}
