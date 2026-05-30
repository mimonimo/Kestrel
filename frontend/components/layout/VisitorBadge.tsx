"use client";

/**
 * Footer 방문자 카운터 — 단일 chip 안에 일접속/누적 통합 (PR 10-CS.3).
 *
 * 칩은 sky 톤 한 개. 숫자만 연두/하늘로 구분.
 * useQuery 가 5분마다 refetch 하면서 자기를 카운트.
 */
import { useQuery } from "@tanstack/react-query";
import { Eye } from "lucide-react";

import { api } from "@/lib/api";

export function VisitorBadge() {
  const { data, isPending } = useQuery({
    queryKey: ["visitors"],
    queryFn: () => api.getVisitors(),
    refetchInterval: 5 * 60_000,
    staleTime: 60_000,
  });
  const today = data?.today ?? 0;
  const total = data?.total ?? 0;

  return (
    <span
      title={`오늘 ${today.toLocaleString()}명 · 누적 ${total.toLocaleString()}명`}
      className="inline-flex items-center gap-1.5 rounded-full border border-sky-300 bg-sky-50 px-2.5 py-0.5 text-[11px] font-medium dark:border-sky-500/40 dark:bg-sky-500/10"
    >
      <Eye className="h-3 w-3 text-sky-700 dark:text-sky-300" />
      <span className="text-emerald-700 dark:text-emerald-300">오늘</span>
      <span className="tabular-nums text-emerald-700 dark:text-emerald-300">
        {isPending ? "—" : today.toLocaleString()}
      </span>
      <span className="text-sky-400 dark:text-sky-500/70">·</span>
      <span className="text-sky-800 dark:text-sky-200">누적</span>
      <span className="tabular-nums text-sky-800 dark:text-sky-200">
        {isPending ? "—" : total.toLocaleString()}
      </span>
    </span>
  );
}
