"use client";

// 설정 > AI 분석 — 새 AI 분석 기록을 기본 공개(공유)로 저장할지 토글.
// OFF(기본): 분석은 비공개로 저장되고 분석 피드에서 개별 공유.
// ON: 분석 실행 즉시 커뮤니티/프로필에 공개.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Globe, Loader2, Lock } from "lucide-react";

import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

export function AnalysisPrefsPanel() {
  const qc = useQueryClient();
  const profile = useQuery({
    queryKey: ["me-profile"],
    queryFn: () => api.getProfile(),
    staleTime: 30_000,
  });
  const on = !!profile.data?.defaultAnalysisPublic;

  const setPref = useMutation({
    mutationFn: (next: boolean) => api.updateProfile({ defaultAnalysisPublic: next }),
    onSuccess: (updated) => {
      qc.setQueryData(["me-profile"], updated);
    },
  });

  const busy = setPref.isPending || profile.isPending;

  return (
    <div className="rounded-2xl border border-neutral-200 bg-white p-6 dark:border-neutral-800 dark:bg-surface-1">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-neutral-900 dark:text-neutral-100">
            {on ? (
              <Globe className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
            ) : (
              <Lock className="h-4 w-4 text-neutral-500" />
            )}
            분석 기록 기본 공개
          </h3>
          <p className="mt-1 text-[13px] leading-relaxed text-neutral-600 dark:text-neutral-400">
            켜면 새로 실행하는 AI 분석이 바로 <strong>공개(공유)</strong>로 저장되어 해당 CVE의
            “커뮤니티 분석”과 내 프로필에 노출됩니다. 끄면(기본) 비공개로 저장되고, 분석 피드에서
            원하는 것만 개별 공유할 수 있어요.
          </p>
        </div>

        {/* 토글 스위치 */}
        <button
          type="button"
          role="switch"
          aria-checked={on}
          disabled={busy}
          onClick={() => setPref.mutate(!on)}
          className={cn(
            "relative mt-0.5 inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors disabled:opacity-60",
            on ? "bg-emerald-500" : "bg-neutral-300 dark:bg-neutral-700",
          )}
        >
          <span
            className={cn(
              "inline-flex h-5 w-5 transform items-center justify-center rounded-full bg-white shadow transition-transform",
              on ? "translate-x-[22px]" : "translate-x-0.5",
            )}
          >
            {busy && <Loader2 className="h-3 w-3 animate-spin text-neutral-400" />}
          </span>
        </button>
      </div>

      {setPref.isError && (
        <p className="mt-3 text-[11px] text-rose-700 dark:text-rose-400">
          설정 저장에 실패했어요. 잠시 후 다시 시도해 주세요.
        </p>
      )}
    </div>
  );
}
