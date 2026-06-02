"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ClipboardList, Loader2, LogIn, Trash2 } from "lucide-react";
import { api, ApiError, type Ticket, type TicketStatus } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { cn } from "@/lib/utils";

// 상태별 활성 칩 톤. 라이트/다크 양쪽에서 충분한 채도·대비를 보장 — 이전엔
// open(미확인) 이 거의 무채색이라 비활성 칩과 시각 차이가 약했고, 다크 톤이
// 너무 짙어서 라이트 모드 캔버스 위에서 까맣게 떠 보이는 회귀 보고가 있었음
// (PR 10-CO 후속). border + ring + 충분한 saturation 으로 active 임을 명확히.
export const STATUS_META: Record<TicketStatus, { label: string; cls: string }> = {
  open: {
    label: "미확인",
    cls: "border-rose-400 bg-rose-50 text-rose-700 ring-1 ring-rose-300/60 dark:border-rose-400/60 dark:bg-rose-500/15 dark:text-rose-200 dark:ring-rose-400/30",
  },
  in_progress: {
    label: "조치 중",
    cls: "border-amber-400 bg-amber-50 text-amber-800 ring-1 ring-amber-300/60 dark:border-amber-400/60 dark:bg-amber-400/15 dark:text-amber-200 dark:ring-amber-400/30",
  },
  resolved: {
    label: "조치 완료",
    cls: "border-emerald-400 bg-emerald-50 text-emerald-800 ring-1 ring-emerald-300/60 dark:border-emerald-400/60 dark:bg-emerald-400/15 dark:text-emerald-200 dark:ring-emerald-400/30",
  },
  ignored: {
    label: "무시",
    // 다크 톤이 neutral-500/15 알파라 dark surface 위에서 검정 칩처럼 표시되던
    // 회귀 수정. solid zinc 로 바꾸고 텍스트 명도도 충분히 끌어올림.
    cls: "border-zinc-400 bg-zinc-200 text-zinc-800 ring-1 ring-zinc-400/60 dark:border-zinc-400/60 dark:bg-zinc-600/50 dark:text-zinc-100 dark:ring-zinc-400/40",
  },
};

const ALL: TicketStatus[] = ["open", "in_progress", "resolved", "ignored"];

interface Props {
  cveId: string;
}

export function TicketControl({ cveId }: Props) {
  const qc = useQueryClient();
  const { user, loading: authLoading } = useAuth();

  const { data, isPending } = useQuery({
    queryKey: ["tickets"],
    queryFn: () => api.listTickets(),
    staleTime: 10_000,
    enabled: !!user, // 비로그인은 fetch 자체 안 함 (헤더 없는 400 회피)
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
        {!authLoading && !user ? (
          <LoginGate cveId={cveId} />
        ) : isPending ? (
          <div className="flex items-center gap-2 text-xs text-neutral-600 dark:text-neutral-500">
            <Loader2 className="h-3 w-3 animate-spin" /> 불러오는 중…
          </div>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-1.5 sm:flex sm:flex-wrap">
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
                className="rounded-full bg-sky-500 text-white hover:bg-sky-600 disabled:opacity-50 dark:bg-sky-500 dark:hover:bg-sky-400"
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

function LoginGate({ cveId }: { cveId: string }) {
  const next = encodeURIComponent(`/cves/${cveId}`);
  return (
    <div className="flex flex-col items-start gap-2 rounded-lg border border-dashed border-neutral-300 bg-neutral-50 p-4 dark:border-neutral-700 dark:bg-surface-2">
      <p className="text-sm text-neutral-800 dark:text-neutral-200">
        대응 상태와 메모는 <span className="font-medium">로그인</span> 후에 저장할 수 있어요.
      </p>
      <p className="text-xs text-neutral-600 dark:text-neutral-400">
        조치 진행 상황을 본인의 계정에 안전하게 보관합니다.
      </p>
      <Link
        href={`/login?next=${next}` as never}
        className="mt-1 inline-flex items-center gap-1.5 rounded-full bg-sky-500 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-sky-600 dark:bg-sky-500 dark:hover:bg-sky-400"
      >
        <LogIn className="h-3 w-3" />
        로그인하기
      </Link>
    </div>
  );
}
