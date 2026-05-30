"use client";

/**
 * Header 의 사용자 메뉴 오른쪽에 표시하는 작은 방문자 카운터 chip (PR 10-CS).
 *
 * - 마운트 시 한 번 + 5분마다 refetch — 매 호출이 자기를 카운트하므로
 *   결과적으로 "지금 활성 사용자" 의 근사가 된다.
 * - 표시: "👁 5 · 누적 27" — 일접속 / 누적 두 숫자만, 최대한 심플하게.
 */
import { useQuery } from "@tanstack/react-query";
import { Eye } from "lucide-react";

import { api } from "@/lib/api";

export function VisitorBadge() {
  const { data } = useQuery({
    queryKey: ["visitors"],
    queryFn: () => api.getVisitors(),
    refetchInterval: 5 * 60_000,
    staleTime: 60_000,
  });
  // 처음 로드 전에도 자리 차지 — placeholder 로 0 표시. 깜빡임 줄임.
  const today = data?.today ?? 0;
  const total = data?.total ?? 0;
  return (
    <span
      title={`오늘 ${today}명 · 누적 ${total}명 방문`}
      className="hidden sm:inline-flex h-8 items-center gap-1.5 rounded-full border border-neutral-200 bg-white px-2.5 text-xs text-neutral-700 dark:border-neutral-700 dark:bg-surface-1 dark:text-neutral-300"
    >
      <Eye className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
      <span className="tabular-nums font-medium text-neutral-900 dark:text-neutral-100">
        {today.toLocaleString()}
      </span>
      <span className="text-neutral-400 dark:text-neutral-500">·</span>
      <span className="tabular-nums text-neutral-600 dark:text-neutral-400">
        {total.toLocaleString()}
      </span>
    </span>
  );
}
