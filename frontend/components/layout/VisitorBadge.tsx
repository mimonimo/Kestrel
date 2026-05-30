"use client";

/**
 * Header 의 사용자 메뉴 오른쪽 방문자 카운터 (PR 10-CS / 확장 CS.1).
 *
 * - 기본 상태: 눈 아이콘 원형 버튼만 (숫자 노출 X).
 * - 클릭 시 popover 가 열려 일접속 / 누적 두 숫자를 보여 줌. 외부 클릭/ESC 로 닫힘.
 * - useQuery 가 5분마다 refetch 하면서 자기를 카운트. popover 여부와 무관.
 */
import { useQuery } from "@tanstack/react-query";
import { Eye } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

export function VisitorBadge() {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);

  const { data, isPending } = useQuery({
    queryKey: ["visitors"],
    queryFn: () => api.getVisitors(),
    refetchInterval: 5 * 60_000,
    staleTime: 60_000,
  });
  const today = data?.today ?? 0;
  const total = data?.total ?? 0;

  // 외부 클릭 / ESC 로 닫기.
  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("mousedown", onClick);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onClick);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div ref={wrapRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-label="방문자 수 보기"
        aria-expanded={open}
        title="방문자 수"
        className={cn(
          "inline-flex h-8 w-8 items-center justify-center rounded-full border transition-colors",
          open
            ? "border-sky-300 bg-sky-50 text-sky-700 dark:border-sky-500/40 dark:bg-sky-500/15 dark:text-sky-200"
            : "border-neutral-200 bg-white text-neutral-600 hover:bg-neutral-50 hover:text-neutral-900 dark:border-neutral-700 dark:bg-surface-1 dark:text-neutral-400 dark:hover:bg-surface-2 dark:hover:text-neutral-100",
        )}
      >
        <Eye className="h-4 w-4" />
      </button>

      {open && (
        <div
          role="dialog"
          className="absolute right-0 bottom-10 z-50 w-44 overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-lg dark:border-neutral-800 dark:bg-surface-1"
        >
          <div className="border-b border-neutral-200 bg-neutral-50 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:border-neutral-800 dark:bg-surface-2/60 dark:text-neutral-500">
            방문자
          </div>
          <dl className="divide-y divide-neutral-200 text-sm dark:divide-neutral-800">
            <Row label="일 접속" value={today} pending={isPending} />
            <Row label="누적" value={total} pending={isPending} />
          </dl>
        </div>
      )}
    </div>
  );
}

function Row({
  label,
  value,
  pending,
}: {
  label: string;
  value: number;
  pending: boolean;
}) {
  return (
    <div className="flex items-baseline justify-between px-3 py-2">
      <dt className="text-xs text-neutral-600 dark:text-neutral-400">{label}</dt>
      <dd className="tabular-nums font-medium text-neutral-900 dark:text-neutral-100">
        {pending ? "—" : value.toLocaleString()}
      </dd>
    </div>
  );
}
