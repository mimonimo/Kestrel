"use client";

import { AlertTriangle, CheckCircle2, Database, Loader2, Sparkles } from "lucide-react";
import { useState } from "react";
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
  const [confirmFull, setConfirmFull] = useState(false);

  const backfill = useMutation({
    mutationFn: (mode: "full" | "delta") => api.mitreBackfill({ mode }),
  });

  // Pull the live MITRE row from /status so progress survives navigation
  // — without this the user loses sight of an in-flight backfill the
  // moment they switch pages, even though the work continues server-side.
  const status = useStatus();
  const mitreRow = status.data?.ingestions?.find((i) => i.source === "mitre");

  const onClickFull = () => {
    if (!confirmFull) {
      setConfirmFull(true);
      return;
    }
    setConfirmFull(false);
    backfill.mutate("full");
  };

  return (
    <div className="space-y-3 rounded-lg border border-neutral-800 bg-surface-1 p-5">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-violet-500/15 text-violet-300 ring-1 ring-violet-500/30">
            <Database className="h-4 w-4" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-neutral-100">
              MITRE cvelistV5 백필
            </h3>
            <p className="mt-1 text-xs text-neutral-500">
              전체 ~340k CVE 를 한 번에 채웁니다.
            </p>
          </div>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 pt-1">
        <Button
          size="md"
          variant="outline"
          disabled={backfill.isPending}
          onClick={() => backfill.mutate("delta")}
        >
          {backfill.isPending && backfill.variables === "delta" ? (
            <Loader2 className="mr-1 h-4 w-4 animate-spin" />
          ) : (
            <Sparkles className="mr-1 h-4 w-4" />
          )}
          최근 14일 델타만
        </Button>
        <Button
          size="md"
          variant="outline"
          disabled={backfill.isPending}
          onClick={onClickFull}
          className={cn(
            confirmFull
              ? "border-amber-500/40 text-amber-200 hover:bg-amber-500/10"
              : "border-violet-500/40 text-violet-200 hover:bg-violet-500/10",
          )}
        >
          {backfill.isPending && backfill.variables === "full" ? (
            <Loader2 className="mr-1 h-4 w-4 animate-spin" />
          ) : confirmFull ? (
            <AlertTriangle className="mr-1 h-4 w-4" />
          ) : (
            <Database className="mr-1 h-4 w-4" />
          )}
          {confirmFull ? "확인하고 전체 백필 실행" : "전체 백필 시작 (~340k)"}
        </Button>
        {confirmFull && !backfill.isPending && (
          <Button
            size="md"
            variant="ghost"
            onClick={() => setConfirmFull(false)}
            className="text-neutral-400"
          >
            취소
          </Button>
        )}
      </div>

      {confirmFull && !backfill.isPending && (
        <p className="rounded border border-amber-500/30 bg-amber-500/10 p-2 text-[11px] text-amber-200">
          첫 실행 시 git clone ~5GB + 340k 행 처리로 30~60분이 소요됩니다.
          백그라운드에서 실행되므로 화면을 닫아도 진행되며, 진행 상황은 위
          새로고침 막대의 MITRE 행으로 확인할 수 있습니다.
        </p>
      )}

      {backfill.data && !backfill.error && (
        <NoticeBox title="백필 시작됨" message={backfill.data.detail} size="sm" />
      )}
      {backfill.error && (
        <ErrorBox
          title="백필 시작 실패"
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
              ? "border-sky-500/30 bg-sky-500/5 text-sky-200"
              : mitreRow.status === "failed"
                ? "border-rose-500/30 bg-rose-500/5 text-rose-200"
                : "border-emerald-500/30 bg-emerald-500/5 text-emerald-200",
          )}
        >
          <div className="flex flex-wrap items-center gap-2">
            {mitreRow.status === "running" ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin text-sky-300" />
            ) : mitreRow.status === "failed" ? (
              <AlertTriangle className="h-3.5 w-3.5 text-rose-300" />
            ) : (
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-300" />
            )}
            <span className="font-medium">
              {mitreRow.status === "running"
                ? "백필 진행 중"
                : mitreRow.status === "failed"
                  ? "마지막 실행 실패"
                  : "마지막 실행 완료"}
            </span>
            {mitreRow.itemsProcessed > 0 && (
              <span className="text-neutral-400">
                · 처리 {formatNumber(mitreRow.itemsProcessed)}건
              </span>
            )}
            {mitreRow.finishedAt && (
              <span className="text-neutral-500">
                · {timeAgo(mitreRow.finishedAt)}
              </span>
            )}
          </div>
          {mitreRow.errorMessage && (
            <p className="mt-1 break-words text-[11px] text-rose-200">
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
