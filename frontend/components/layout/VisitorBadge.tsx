"use client";

/**
 * Footer 의 누적 방문자 표시 (PR 10-CS.5).
 *
 * 틀/배경 없이 텍스트로만. 누적 한 숫자만.
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
  const total = data?.total ?? 0;

  return (
    <span
      title={`누적 ${total.toLocaleString()}명 방문`}
      className="inline-flex items-center gap-1 text-[11px] text-sky-700 dark:text-sky-300"
    >
      <Eye className="h-3 w-3" />
      <span>누적</span>
      <span className="tabular-nums font-medium">
        {isPending ? "—" : total.toLocaleString()}
      </span>
    </span>
  );
}
