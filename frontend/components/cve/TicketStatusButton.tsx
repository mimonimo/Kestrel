"use client";

// 대응 상태를 별표·공유 버튼 옆에 두는 컴팩트 태그 셀렉터.
// 큰 카드(박스) 대신 작은 칩(색 점 + 라벨) + 드롭다운으로 상태만 선택/해제.
import Link from "next/link";
import type { Route } from "next";
import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, ChevronDown, Loader2, Tag } from "lucide-react";

import { api, type TicketStatus } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { STATUS_META } from "./TicketControl";
import { cn } from "@/lib/utils";

const ALL: TicketStatus[] = ["open", "in_progress", "resolved", "ignored"];

// 상태별 색 점 — 칩/드롭다운에서 태그 색상으로 사용.
const DOT: Record<TicketStatus, string> = {
  open: "bg-rose-500",
  in_progress: "bg-amber-500",
  resolved: "bg-emerald-500",
  ignored: "bg-zinc-400",
};

export function TicketStatusButton({ cveId }: { cveId: string }) {
  const qc = useQueryClient();
  const { user } = useAuth();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const { data } = useQuery({
    queryKey: ["tickets"],
    queryFn: () => api.listTickets(),
    staleTime: 10_000,
    enabled: !!user,
  });
  const ticket = data?.items.find((t) => t.cveId === cveId);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener("mousedown", onDoc);
    return () => window.removeEventListener("mousedown", onDoc);
  }, [open]);

  const invalidate = () => qc.invalidateQueries({ queryKey: ["tickets"] });
  const upsert = useMutation({
    mutationFn: (status: TicketStatus) =>
      api.upsertTicket({ cveId, status, note: ticket?.note ?? null }),
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: () => api.deleteTicket(cveId),
    onSuccess: invalidate,
  });
  const busy = upsert.isPending || remove.isPending;

  // 비로그인 — 작은 로그인 유도 칩.
  if (!user) {
    return (
      <Link
        href={`/login?next=${encodeURIComponent(`/cve/${cveId}`)}` as Route}
        title="대응 상태 (로그인 필요)"
        className="inline-flex items-center gap-1.5 rounded-full border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-500 transition-colors hover:border-sky-400 hover:text-sky-700 dark:border-neutral-700 dark:hover:border-sky-500/60 dark:hover:text-sky-200"
      >
        <Tag className="h-3.5 w-3.5" />
        대응
      </Link>
    );
  }

  const cur = ticket?.status;
  const meta = cur ? STATUS_META[cur] : null;

  return (
    <div ref={ref} className="relative inline-block">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        title="대응 상태"
        aria-haspopup="menu"
        aria-expanded={open}
        className={cn(
          "inline-flex items-center gap-1.5 rounded-full border px-2 py-1 text-xs font-medium transition-colors",
          meta
            ? meta.cls
            : "border-neutral-300 text-neutral-500 hover:border-sky-400 hover:text-sky-700 dark:border-neutral-700 dark:hover:border-sky-500/60 dark:hover:text-sky-200",
        )}
      >
        {busy ? (
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
        ) : meta ? (
          <span className={cn("h-2 w-2 rounded-full", DOT[cur!])} />
        ) : (
          <Tag className="h-3.5 w-3.5" />
        )}
        {meta ? meta.label : "대응"}
        <ChevronDown className="h-3 w-3 opacity-60" />
      </button>

      {open && (
        <div
          role="menu"
          className="absolute left-0 top-full z-50 mt-1 w-40 overflow-hidden rounded-lg border border-neutral-200 bg-white p-1 shadow-lg dark:border-neutral-800 dark:bg-surface-1"
        >
          {ALL.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => {
                upsert.mutate(s);
                setOpen(false);
              }}
              className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-xs text-neutral-700 transition-colors hover:bg-neutral-100 dark:text-neutral-200 dark:hover:bg-surface-2"
            >
              <span className={cn("h-2.5 w-2.5 rounded-full", DOT[s])} />
              {STATUS_META[s].label}
              {cur === s && <Check className="ml-auto h-3.5 w-3.5 text-sky-600 dark:text-sky-300" />}
            </button>
          ))}
          {ticket && (
            <button
              type="button"
              onClick={() => {
                remove.mutate();
                setOpen(false);
              }}
              className="mt-1 flex w-full items-center gap-2 border-t border-neutral-200 px-2 py-1.5 text-xs text-rose-600 transition-colors hover:bg-rose-50 dark:border-neutral-800 dark:text-rose-300 dark:hover:bg-rose-500/10"
            >
              상태 해제
            </button>
          )}
        </div>
      )}
    </div>
  );
}
