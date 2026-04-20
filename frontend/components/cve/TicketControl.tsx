"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Trash2 } from "lucide-react";
import { api, ApiError, type Ticket, type TicketStatus } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export const STATUS_META: Record<TicketStatus, { label: string; cls: string }> = {
  open: { label: "미확인", cls: "border-neutral-700 bg-neutral-800/60 text-neutral-200" },
  in_progress: {
    label: "조치 중",
    cls: "border-amber-400/40 bg-amber-400/10 text-amber-200",
  },
  resolved: {
    label: "조치 완료",
    cls: "border-emerald-400/40 bg-emerald-400/10 text-emerald-200",
  },
  ignored: {
    label: "무시",
    cls: "border-neutral-700 bg-neutral-800/40 text-neutral-500",
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
      setError(e instanceof ApiError ? e.message : "티켓 저장에 실패했습니다."),
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
    <section className="rounded-lg border border-neutral-800 bg-surface-1 p-4">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-neutral-200">대응 상태</h3>
        {ticket && (
          <button
            type="button"
            onClick={() => {
              if (confirm("이 CVE의 티켓을 삭제하시겠습니까?")) remove.mutate();
            }}
            className="inline-flex items-center gap-1 text-xs text-neutral-500 hover:text-red-400"
            aria-label="티켓 삭제"
          >
            <Trash2 className="h-3 w-3" />
            제거
          </button>
        )}
      </div>

      {isPending ? (
        <div className="flex items-center gap-2 text-xs text-neutral-500">
          <Loader2 className="h-3 w-3 animate-spin" /> 불러오는 중…
        </div>
      ) : (
        <>
          <div className="mb-3 flex flex-wrap gap-1.5">
            {ALL.map((s) => {
              const active = (ticket?.status ?? "open") === s && !!ticket;
              return (
                <button
                  key={s}
                  type="button"
                  onClick={() => upsert.mutate({ status: s, note })}
                  disabled={upsert.isPending}
                  className={cn(
                    "rounded-md border px-2.5 py-1 text-xs font-medium transition",
                    active
                      ? STATUS_META[s].cls
                      : "border-neutral-700 text-neutral-400 hover:border-neutral-500 hover:text-neutral-200",
                  )}
                  aria-pressed={active}
                >
                  {STATUS_META[s].label}
                </button>
              );
            })}
          </div>

          <textarea
            className="block min-h-[60px] w-full rounded-md border border-neutral-800 bg-surface-2 p-2 text-xs text-neutral-100 placeholder:text-neutral-500 focus:border-neutral-600 focus:outline-none"
            placeholder="대응 메모 (선택)"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            maxLength={4000}
          />
          {error && <p className="mt-1 text-xs text-red-400">{error}</p>}
          <div className="mt-2 flex items-center justify-between text-[11px] text-neutral-500">
            <span>{ticket ? `최근 갱신 ${new Date(ticket.updatedAt).toLocaleString("ko-KR")}` : "아직 등록되지 않음"}</span>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => upsert.mutate({ status: ticket?.status ?? "open", note })}
              disabled={upsert.isPending || (note === (ticket?.note ?? ""))}
            >
              메모 저장
            </Button>
          </div>
        </>
      )}
    </section>
  );
}
