"use client";

// Newest critical CVEs at a glance — operators need to know what hit
// the corpus today even before they open the list. Each card is a
// direct link into the detail page.

import Link from "next/link";
import type { Route } from "next";
import { AlertTriangle } from "lucide-react";
import { useQuery } from "@tanstack/react-query";

import { WidgetCard } from "./WidgetCard";
import { api, type DashboardRecentItem } from "@/lib/api";

function formatRelative(iso: string | null): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "방금";
  if (mins < 60) return `${mins}분 전`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}시간 전`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}일 전`;
  const months = Math.floor(days / 30);
  return `${months}개월 전`;
}

export function RecentCriticalPanel() {
  const q = useQuery({
    queryKey: ["dashboard", "insights", "recent-critical"],
    queryFn: () => api.getDashboardInsights({ recentLimit: 5 }),
    staleTime: 60_000,
    refetchInterval: 60_000,
  });

  const items: DashboardRecentItem[] = q.data?.recentCritical ?? [];

  return (
    <WidgetCard
      title="최근 Critical"
      description="가장 최근에 등록된 CVSS 9.0+ 사례 5건"
      isLoading={q.isLoading}
      error={q.error as Error | null}
      actions={
        <Link
          href={"/cves?severity=critical" as Route}
          className="text-[11px] font-medium text-rose-700 hover:text-rose-900 dark:text-rose-300 dark:hover:text-rose-200"
        >
          전체 보기 →
        </Link>
      }
    >
      {items.length === 0 ? (
        <p className="text-xs text-neutral-600 dark:text-neutral-500">
          이번 기간에 Critical 등급이 없습니다.
        </p>
      ) : (
        <ul className="divide-y divide-neutral-200 dark:divide-neutral-800">
          {items.map((c) => (
            <li key={c.cveId} className="py-2 first:pt-0 last:pb-0">
              <Link
                href={`/cve/${encodeURIComponent(c.cveId)}` as Route}
                className="block rounded-md px-1 py-1 hover:bg-rose-50 dark:hover:bg-rose-500/5"
              >
                <div className="flex items-baseline justify-between gap-2">
                  <span className="flex items-center gap-1.5 font-mono text-[12px] font-semibold text-neutral-900 dark:text-neutral-100">
                    <AlertTriangle className="h-3 w-3 text-rose-600 dark:text-rose-400" />
                    {c.cveId}
                  </span>
                  <span className="shrink-0 tabular-nums text-[10px] text-neutral-500 dark:text-neutral-500">
                    {formatRelative(c.publishedAt)}
                  </span>
                </div>
                <p className="mt-0.5 line-clamp-2 text-[11px] leading-snug text-neutral-700 dark:text-neutral-400">
                  {c.title}
                </p>
                {c.cvssScore != null && (
                  <div className="mt-1 inline-flex items-center gap-1 rounded-full bg-rose-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-rose-800 dark:text-rose-200">
                    CVSS {c.cvssScore.toFixed(1)}
                  </div>
                )}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </WidgetCard>
  );
}
