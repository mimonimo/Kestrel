"use client";

/**
 * Footer 의 방문자 카운터 — 일접속(연두) / 누적(하늘) 두 chip (PR 10-CS / 확장 CS.3).
 *
 * 한 눈에 두 지표 구분되도록 색상 분리. 토글 없음, 항상 표시.
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
    <span className="inline-flex items-center gap-1.5">
      <span
        title={`오늘 ${today.toLocaleString()}명 방문`}
        className="inline-flex items-center gap-1 rounded-full border border-emerald-300 bg-emerald-50 px-2 py-0.5 text-[11px] font-medium text-emerald-800 dark:border-emerald-500/40 dark:bg-emerald-500/15 dark:text-emerald-200"
      >
        <Eye className="h-3 w-3" />
        <span>오늘</span>
        <span className="tabular-nums">
          {isPending ? "—" : today.toLocaleString()}
        </span>
      </span>
      <span
        title={`누적 ${total.toLocaleString()}명 방문`}
        className="inline-flex items-center gap-1 rounded-full border border-sky-300 bg-sky-50 px-2 py-0.5 text-[11px] font-medium text-sky-800 dark:border-sky-500/40 dark:bg-sky-500/15 dark:text-sky-200"
      >
        <Eye className="h-3 w-3" />
        <span>누적</span>
        <span className="tabular-nums">
          {isPending ? "—" : total.toLocaleString()}
        </span>
      </span>
    </span>
  );
}
