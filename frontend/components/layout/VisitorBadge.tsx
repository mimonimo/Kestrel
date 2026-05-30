"use client";

/**
 * Footer 의 방문자 표시 (PR 10-CS.6).
 *
 * 아이콘·틀 없이 텍스트로만. "일 방문자 X / 누적 방문자 Y".
 */
import { useQuery } from "@tanstack/react-query";

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
      title={`일 방문자 ${today.toLocaleString()}명 · 누적 ${total.toLocaleString()}명`}
      className="inline-flex items-center gap-1 text-[11px]"
    >
      <span className="text-emerald-700 dark:text-emerald-300">일 방문자</span>
      <span className="tabular-nums font-medium text-emerald-700 dark:text-emerald-300">
        {isPending ? "—" : today.toLocaleString()}
      </span>
      <span className="text-neutral-400 dark:text-neutral-500">/</span>
      <span className="text-sky-700 dark:text-sky-300">누적 방문자</span>
      <span className="tabular-nums font-medium text-sky-700 dark:text-sky-300">
        {isPending ? "—" : total.toLocaleString()}
      </span>
    </span>
  );
}
