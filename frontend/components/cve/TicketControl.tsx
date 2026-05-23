"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ClipboardList, Loader2, Trash2 } from "lucide-react";
import { api, ApiError, type Ticket, type TicketStatus } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { cn } from "@/lib/utils";

// Status chip tinting — paired light/dark variants for every status so
// the active pill is legible in either theme without falling back to
// the dark-only neutral-800 background that flattened in light mode.
export const STATUS_META: Record<TicketStatus, { label: string; cls: string }> = {
  open: {
    label: "미확인",
    cls: "border-neutral-300 bg-neutral-100 text-neutral-800 dark:border-neutral-700 dark:bg-neutral-800/60 dark:text-neutral-200",
  },
  in_progress: {
    label: "조치 중",
    cls: "border-amber-300 bg-amber-50 text-amber-800 dark:border-amber-400/40 dark:bg-amber-400/10 dark:text-amber-200",
  },
  resolved: {
    label: "조치 완료",
    cls: "border-emerald-300 bg-emerald-50 text-emerald-800 dark:border-emerald-400/40 dark:bg-emerald-400/10 dark:text-emerald-200",
  },
  ignored: {
    label: "무시",
    cls: "border-neutral-300 bg-neutral-50 text-neutral-500 dark:border-neutral-700 dark:bg-neutral-800/40 dark:text-neutral-500",
  },
};

const ALL: TicketStatus[] = ["open", "in_progress", "resolved", "ignored"];

interface Props {
  cveId: string;
}

export function TicketControl({ cveId }: Props) {
  const qc = useQueryClient();

  const { data, isPending } = useQuery({
    queryKey: ["tickets"],
    queryFn: () => api.listTickets(),
    staleTime: 10_000,
  });
  const ticket = data?.items.find((t) => t.cveId === cveId);

  const [note, setNote] = useState(ticket?.note ?? "");
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setNote(ticket?.note ?? "");
  }, [ticket?.id, ticket?.note]);

  const upsert = useMutation({
    mutationFn: (next: { status: TicketStatus; note?: string | null }) =>
      api.upsertTicket({ cveId, status: next.status, note: next.note ?? null }),
    onSuccess: (saved: Ticket) => {
      setError(null);
      qc.setQueryData<typeof data>(["tickets"], (prev) => {
        if (!prev) return prev;
        const filtered = prev.items.filter((t) => t.cveId !== saved.cveId);
        const counts = { ...prev.counts };
        if (ticket) counts[ticket.status] = Math.max(0, (counts[ticket.status] ?? 0) - 1);
        counts[saved.status] = (counts[saved.status] ?? 0) + 1;
        return { ...prev, items: [saved, ...filtered], total: filtered.length + 1, counts };
      });
    },
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : "대응 상태 저장에 실패했어요."),
  });

  const remove = useMutation({
    mutationFn: () => api.deleteTicket(cveId),
    onSuccess: () =>
      qc.setQueryData<typeof data>(["tickets"], (prev) => {
        if (!prev) return prev;
        const removed = prev.items.find((t) => t.cveId === cveId);
        const counts = { ...prev.counts };
        if (removed) counts[removed.status] = Math.max(0, (counts[removed.status] ?? 0) - 1);
        return {
          ...prev,
          items: prev.items.filter((t) => t.cveId !== cveId),
          total: Math.max(0, prev.total - 1),
          counts,
        };
      }),
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ClipboardList className="h-4 w-4 text-sky-600 dark:text-sky-400" />
          <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-600 dark:text-neutral-500">
            대응 상태
          </h2>
        </div>
        {ticket && (
          <button
            type="button"
            onClick={() => {
              if (confirm("이 CVE 의 대응 상태를 삭제할까요?")) remove.mutate();
            }}
            className="inline-flex items-center gap-1 rounded-full px-2 py-1 text-[11px] text-neutral-500 hover:bg-rose-50 hover:text-rose-700 dark:hover:bg-rose-500/15 dark:hover:text-rose-300"
            aria-label="대응 상태 삭제"
          >
            <Trash2 className="h-3 w-3" />
            삭제
          </button>
        )}
      </CardHeader>
      <CardContent className="space-y-3">
        {isPending ? (
          <div className="flex items-center gap-2 text-xs text-neutral-600 dark:text-neutral-500">
            <Loader2 className="h-3 w-3 animate-spin" /> 불러오는 중…
          </div>
        ) : (
          <>
            <div className="flex flex-wrap gap-1.5">
              {ALL.map((s) => {
                const active = (ticket?.status ?? "open") === s && !!ticket;
                return (
                  <button
                    key={s}
                    type="button"
                    onClick={() => upsert.mutate({ status: s, note })}
                    disabled={upsert.isPending}
                    className={cn(
                      "rounded-full border px-3 py-1 text-xs font-medium transition-all duration-150 active:scale-95",
                      active
                        ? STATUS_META[s].cls
                        : "border-neutral-300 text-neutral-700 hover:border-sky-400 hover:text-sky-700 dark:border-neutral-700 dark:text-neutral-400 dark:hover:border-sky-500/60 dark:hover:text-sky-200",
                    )}
                    aria-pressed={active}
                  >
                    {STATUS_META[s].label}
                  </button>
                );
              })}
            </div>

            <textarea
              className="block min-h-[64px] w-full rounded-lg border border-neutral-300 bg-white p-2.5 text-xs text-neutral-900 placeholder:text-neutral-500 focus:border-sky-500 focus:outline-none dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100"
              placeholder="대응 메모 (선택)"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              maxLength={4000}
            />
            {error && <p className="text-xs text-rose-700 dark:text-rose-300">{error}</p>}
            <div className="flex items-center justify-between text-[11px] text-neutral-600 dark:text-neutral-500">
              <span>
                {ticket
                  ? `최근 갱신 ${new Date(ticket.updatedAt).toLocaleString("ko-KR")}`
                  : "아직 등록되지 않은 상태입니다"}
              </span>
              <Button
                type="button"
                size="sm"
                onClick={() => upsert.mutate({ status: ticket?.status ?? "open", note })}
                disabled={upsert.isPending || note === (ticket?.note ?? "")}
                className="rounded-full bg-sky-600 text-white hover:bg-sky-700 disabled:opacity-50 dark:bg-sky-500 dark:hover:bg-sky-400"
              >
                메모 저장
              </Button>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
