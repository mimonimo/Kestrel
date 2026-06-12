"use client";

// 내 프로필에서 "공유한 분석"을 관리 — 공개/비공개 토글, 삭제, 본문 보기.
// 데이터는 owner 스코프(/me/analyses)라 비공개 분석까지 포함한다.
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Globe, Loader2, Lock, ScrollText, Trash2 } from "lucide-react";

import { api, type AnalysisList } from "@/lib/api";
import { ErrorBox } from "@/components/ui/feedback-box";
import { AnalysisDetailModal } from "@/components/community/AnalysisDetailModal";
import { formatRelativeKo } from "@/lib/format";
import { cn } from "@/lib/utils";

export function MyAnalysesManager() {
  const qc = useQueryClient();
  const [openId, setOpenId] = useState<string | null>(null);

  const list = useQuery({
    queryKey: ["my-analyses"],
    queryFn: () => api.listMyAnalyses({ limit: 100 }),
    staleTime: 10_000,
  });

  // 토글/삭제 후 공개 프로필·CVE 상세·커뮤니티 피드 표시를 모두 갱신.
  const invalidateSharedViews = () => {
    qc.invalidateQueries({ queryKey: ["community-analyses"] });
    qc.invalidateQueries({ queryKey: ["cve-community-analyses"] });
    qc.invalidateQueries({ queryKey: ["user-profile"] });
  };

  const toggle = useMutation({
    mutationFn: ({ id, visibility }: { id: string; visibility: "public" | "private" }) =>
      api.updateAnalysisRecord(id, { visibility }),
    onSuccess: (updated) => {
      qc.setQueryData<AnalysisList | undefined>(["my-analyses"], (prev) =>
        prev
          ? {
              ...prev,
              items: prev.items.map((a) =>
                a.id === updated.id ? { ...a, visibility: updated.visibility } : a,
              ),
            }
          : prev,
      );
      invalidateSharedViews();
    },
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.deleteAnalysisRecord(id),
    onSuccess: (_v, id) => {
      qc.setQueryData<AnalysisList | undefined>(["my-analyses"], (prev) =>
        prev
          ? { ...prev, items: prev.items.filter((a) => a.id !== id), total: Math.max(0, prev.total - 1) }
          : prev,
      );
      invalidateSharedViews();
    },
  });

  const items = list.data?.items ?? [];

  return (
    <section className="mt-8">
      <h2 className="mb-2 flex items-center gap-1.5 text-sm font-semibold text-neutral-700 dark:text-neutral-300">
        <ScrollText className="h-4 w-4" /> 내 분석 관리 ({items.length})
      </h2>
      <p className="mb-3 text-xs text-neutral-500 dark:text-neutral-500">
        공개로 전환한 분석은 해당 CVE 상세의 “커뮤니티 분석”과 내 프로필에 노출됩니다. 언제든 비공개로 되돌리거나 삭제할 수 있어요.
      </p>

      {list.isPending ? (
        <div className="flex items-center gap-2 py-6 text-sm text-neutral-500">
          <Loader2 className="h-4 w-4 animate-spin" /> 불러오는 중…
        </div>
      ) : list.isError ? (
        <ErrorBox title="내 분석을 불러오지 못했습니다" message="잠시 후 다시 시도해 주세요." />
      ) : items.length === 0 ? (
        <p className="rounded-lg border border-dashed border-neutral-300 px-3 py-6 text-center text-xs text-neutral-500 dark:border-neutral-700">
          아직 분석한 기록이 없어요. CVE 상세에서 AI 심층 분석을 먼저 실행해 주세요.
        </p>
      ) : (
        <ul className="space-y-2">
          {items.map((a) => {
            const isPublic = a.visibility === "public";
            const next = isPublic ? "private" : "public";
            const toggling = toggle.isPending && toggle.variables?.id === a.id;
            const deleting = remove.isPending && remove.variables === a.id;
            return (
              <li
                key={a.id}
                className="flex items-start gap-3 rounded-lg border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-surface-1"
              >
                {/* 본문 — 클릭 시 상세 모달 */}
                <button
                  type="button"
                  onClick={() => setOpenId(a.id)}
                  className="min-w-0 flex-1 text-left"
                >
                  <div className="flex flex-wrap items-baseline gap-x-2 text-xs">
                    <span className="font-mono font-semibold text-sky-700 dark:text-sky-300">{a.cveId}</span>
                    <span className="text-neutral-400">·</span>
                    <span className="tabular-nums text-neutral-500 dark:text-neutral-500">
                      {formatRelativeKo(a.createdAt)}
                    </span>
                    <span
                      className={cn(
                        "rounded-full px-1.5 py-0.5 text-[10px] font-medium",
                        isPublic
                          ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-200"
                          : "bg-neutral-100 text-neutral-600 dark:bg-surface-2 dark:text-neutral-400",
                      )}
                    >
                      {isPublic ? "공개" : "비공개"}
                    </span>
                  </div>
                  {a.title && (
                    <p className="mt-1 truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">
                      {a.title}
                    </p>
                  )}
                  <p className="mt-0.5 line-clamp-2 text-[11px] leading-relaxed text-neutral-600 dark:text-neutral-400">
                    {a.excerpt}
                  </p>
                </button>

                {/* 관리 액션 */}
                <div className="flex shrink-0 flex-col items-stretch gap-1.5">
                  <button
                    type="button"
                    onClick={() => toggle.mutate({ id: a.id, visibility: next })}
                    disabled={toggling}
                    title={isPublic ? "비공개로 전환" : "공개로 전환"}
                    className={cn(
                      "inline-flex items-center justify-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-60",
                      isPublic
                        ? "border-emerald-300 bg-emerald-50 text-emerald-800 hover:bg-emerald-100 dark:border-emerald-500/40 dark:bg-emerald-500/15 dark:text-emerald-200"
                        : "border-neutral-300 bg-white text-neutral-700 hover:border-violet-400 hover:text-violet-700 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-300 dark:hover:border-violet-500/60 dark:hover:text-violet-200",
                    )}
                  >
                    {toggling ? (
                      <Loader2 className="h-3 w-3 animate-spin" />
                    ) : isPublic ? (
                      <Globe className="h-3 w-3" />
                    ) : (
                      <Lock className="h-3 w-3" />
                    )}
                    {isPublic ? "공개됨" : "공유"}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      if (confirm("이 분석을 삭제할까요? 되돌릴 수 없습니다.")) remove.mutate(a.id);
                    }}
                    disabled={deleting}
                    title="삭제"
                    className="inline-flex items-center justify-center gap-1 rounded-full border border-red-300 px-3 py-1.5 text-xs font-medium text-red-700 transition-colors hover:bg-red-50 disabled:opacity-60 dark:border-red-900/50 dark:text-red-300 dark:hover:bg-red-950/40"
                  >
                    {deleting ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />}
                    삭제
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      )}

      <AnalysisDetailModal
        analysisId={openId}
        summary={items.find((a) => a.id === openId) ?? null}
        onClose={() => setOpenId(null)}
      />
    </section>
  );
}
