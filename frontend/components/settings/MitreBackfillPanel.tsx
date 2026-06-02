"use client";

import { AlertTriangle, CheckCircle2, Database, Loader2, Sparkles } from "lucide-react";
import { useMutation } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { useStatus } from "@/hooks/useStatus";
import { Button } from "@/components/ui/button";
import { ErrorBox, NoticeBox } from "@/components/ui/feedback-box";
import { cn } from "@/lib/utils";
import { timeAgo } from "@/lib/utils";

function formatNumber(n: number): string {
  return n.toLocaleString("ko-KR");
}

export function MitreBackfillPanel() {
  const backfill = useMutation({
    mutationFn: (mode: "full" | "delta") => api.mitreBackfill({ mode }),
  });

  // Pull the live MITRE row from /status so progress survives navigation.
  const status = useStatus();
  const mitreRow = status.data?.ingestions?.find((i) => i.source === "mitre");

  return (
    <div className="space-y-3 rounded-lg border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-surface-1">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-violet-500/20 text-violet-700 ring-1 ring-violet-500/30 dark:bg-violet-500/15 dark:text-violet-300">
            <Database className="h-4 w-4" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
              CVE 데이터 갱신
            </h3>
          </div>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 pt-1">
        <Button
          size="md"
          disabled={backfill.isPending}
          onClick={() => backfill.mutate("delta")}
        >
          {backfill.isPending && backfill.variables === "delta" ? (
            <Loader2 className="mr-1 h-4 w-4 animate-spin" />
          ) : (
            <Sparkles className="mr-1 h-4 w-4" />
          )}
          최근 14일 갱신
        </Button>
      </div>

      {backfill.data && !backfill.error && (
        <NoticeBox title="가져오기 시작됨" message={backfill.data.detail} size="sm" />
      )}
      {backfill.error && (
        <ErrorBox
          title="가져오기 시작 실패"
          message={(backfill.error as Error).message}
          size="sm"
        />
      )}

      {/* ── 진행 상황 (페이지 떠났다 와도 유지됨) ────────────────── */}
      {mitreRow && (
        <div
          className={cn(
            "rounded-md border p-3 text-xs",
            mitreRow.status === "running"
              ? "border-sky-500/40 bg-sky-500/10 text-sky-900 dark:bg-sky-500/5 dark:text-sky-200"
              : mitreRow.status === "failed"
                ? "border-rose-500/40 bg-rose-500/10 text-rose-900 dark:bg-rose-500/5 dark:text-rose-200"
                : "border-emerald-500/40 bg-emerald-500/10 text-emerald-900 dark:bg-emerald-500/5 dark:text-emerald-200",
          )}
        >
          <div className="flex flex-wrap items-center gap-2">
            {mitreRow.status === "running" ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin text-sky-700 dark:text-sky-300" />
            ) : mitreRow.status === "failed" ? (
              <AlertTriangle className="h-3.5 w-3.5 text-rose-700 dark:text-rose-300" />
            ) : (
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-700 dark:text-emerald-300" />
            )}
            <span className="font-medium">
              {mitreRow.status === "running"
                ? "가져오는 중"
                : mitreRow.status === "failed"
                  ? "마지막 실행 실패"
                  : "마지막 실행 완료"}
            </span>
            {mitreRow.itemsProcessed > 0 && (
              <span className="text-neutral-700 dark:text-neutral-400">
                · 처리 {formatNumber(mitreRow.itemsProcessed)}건
              </span>
            )}
            {mitreRow.finishedAt && (
              <span className="text-neutral-600 dark:text-neutral-500">
                · {timeAgo(mitreRow.finishedAt)}
              </span>
            )}
          </div>
          {mitreRow.errorMessage && (
            <p className="mt-1 break-words text-[11px] text-rose-800 dark:text-rose-200">
              {mitreRow.errorMessage}
            </p>
          )}
          <p className="mt-1 text-[11px] text-neutral-500">
            이 카드는 60초마다 자동으로 갱신됩니다 — 다른 페이지에 갔다 와도
            서버에서 진행이 계속되므로 상태는 유지됩니다.
          </p>
        </div>
      )}
    </div>
  );
}
