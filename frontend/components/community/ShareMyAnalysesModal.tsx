"use client";

/**
 * "내 분석 공유하기" 모달 — 분석 피드에서 호출.
 *
 * 로그인 사용자의 모든 분석(/me/analyses) 을 시간 역순으로 보여 주고,
 * 각 항목에 공개/비공개 토글 (PATCH /analyses/{id}) 을 제공.
 * 토글 즉시 커뮤니티 피드 쿼리도 무효화돼 반영.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Globe, Lock, Loader2, Share2, X } from "lucide-react";
import { useEffect } from "react";

import { api, type AnalysisList } from "@/lib/api";
import { ErrorBox } from "@/components/ui/feedback-box";
import { formatRelativeKo } from "@/lib/format";
import { cn } from "@/lib/utils";

interface Props {
  open: boolean;
  onClose: () => void;
}

export function ShareMyAnalysesModal({ open, onClose }: Props) {
  const qc = useQueryClient();
  const list = useQuery({
    queryKey: ["my-analyses"],
    queryFn: () => api.listMyAnalyses({ limit: 100 }),
    enabled: open,
    staleTime: 10_000,
  });

  const toggle = useMutation({
    mutationFn: ({ id, visibility }: { id: string; visibility: "public" | "private" }) =>
      api.updateAnalysisRecord(id, { visibility }),
    onSuccess: (updated) => {
      // 낙관적 갱신 — 내 분석 + 커뮤니티 피드 모두 무효화.
      qc.setQueryData<AnalysisList | undefined>(["my-analyses"], (prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          items: prev.items.map((a) =>
            a.id === updated.id ? { ...a, visibility: updated.visibility } : a,
          ),
        };
      });
      qc.invalidateQueries({ queryKey: ["community-analyses"] });
    },
  });

  // ESC 닫기 + body scroll 잠금
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-neutral-950/60 px-4 py-10 backdrop-blur-sm animate-in fade-in duration-150"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="relative w-full max-w-2xl rounded-2xl border border-neutral-200 bg-white shadow-2xl shadow-black/20 dark:border-neutral-800 dark:bg-surface-1 dark:shadow-black/50 animate-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        <button
          type="button"
          onClick={onClose}
          aria-label="닫기"
          className="absolute right-3 top-3 z-10 inline-flex h-8 w-8 items-center justify-center rounded-full text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
        >
          <X className="h-4 w-4" />
        </button>

        <header className="border-b border-neutral-200 px-6 py-4 dark:border-neutral-800">
          <div className="flex items-center gap-2 text-neutral-900 dark:text-neutral-100">
            <Share2 className="h-4 w-4 text-violet-600 dark:text-violet-400" />
            <h2 className="text-base font-semibold">내 분석 공유하기</h2>
          </div>
          <p className="mt-1 text-xs text-neutral-600 dark:text-neutral-500">
            공개로 전환한 분석은 즉시 커뮤니티 분석 피드에 노출됩니다.
            언제든 다시 비공개로 되돌릴 수 있어요.
          </p>
        </header>

        <div className="max-h-[60vh] overflow-y-auto px-4 py-3">
          {list.isPending ? (
            <div className="flex items-center gap-2 px-2 py-6 text-sm text-neutral-600 dark:text-neutral-500">
              <Loader2 className="h-4 w-4 animate-spin" /> 내 분석을 불러오는 중…
            </div>
          ) : list.isError ? (
            <div className="px-2 py-4">
              <ErrorBox
                title="내 분석을 불러오지 못했습니다"
                message="잠시 후 다시 시도해 주세요."
              />
            </div>
          ) : !list.data || list.data.items.length === 0 ? (
            <p className="rounded-lg border border-dashed border-neutral-300 bg-neutral-50 px-4 py-8 text-center text-xs text-neutral-700 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-400">
              아직 분석한 기록이 없어요. CVE 상세에서 AI 심층 분석을 먼저 실행해 주세요.
            </p>
          ) : (
            <ul className="space-y-2">
              {list.data.items.map((a) => {
                const isPublic = a.visibility === "public";
                const next = isPublic ? "private" : "public";
                const pending = toggle.isPending && toggle.variables?.id === a.id;
                return (
                  <li
                    key={a.id}
                    className="flex items-start gap-3 rounded-lg border border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-surface-1"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-baseline gap-x-2 text-xs">
                        <span className="rounded-full bg-violet-100 px-2 py-0.5 font-medium text-violet-800 dark:bg-violet-500/15 dark:text-violet-200">
                          {a.cveId}
                        </span>
                        <span className="text-neutral-500 dark:text-neutral-500">·</span>
                        <span className="tabular-nums text-neutral-600 dark:text-neutral-500">
                          {formatRelativeKo(a.createdAt)}
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
                    </div>
                    <button
                      type="button"
                      onClick={() => toggle.mutate({ id: a.id, visibility: next })}
                      disabled={pending}
                      className={cn(
                        "inline-flex shrink-0 items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-medium transition-colors",
                        isPublic
                          ? "border-emerald-300 bg-emerald-50 text-emerald-800 hover:bg-emerald-100 dark:border-emerald-500/40 dark:bg-emerald-500/15 dark:text-emerald-200 dark:hover:bg-emerald-500/25"
                          : "border-neutral-300 bg-white text-neutral-700 hover:border-violet-400 hover:text-violet-700 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-300 dark:hover:border-violet-500/60 dark:hover:text-violet-200",
                        "disabled:cursor-not-allowed disabled:opacity-60",
                      )}
                      title={isPublic ? "비공개로 전환" : "커뮤니티에 공개"}
                    >
                      {pending ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : isPublic ? (
                        <Globe className="h-3 w-3" />
                      ) : (
                        <Lock className="h-3 w-3" />
                      )}
                      {isPublic ? "공개됨" : "공유"}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
