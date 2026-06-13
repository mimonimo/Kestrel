"use client";

// 공용 분석 본문 모달 — 커뮤니티 분석 피드(AnalysisFeed)와 CVE 상세의
// "커뮤니티 분석"(CveCommunity) 양쪽에서 재사용한다.
// 요약(summary)으로 헤더를 즉시 그리고, 본문(result_md)은 클릭 시 lazy fetch.
import Link from "next/link";
import type { Route } from "next";
import { useQuery } from "@tanstack/react-query";
import { ExternalLink, Loader2, User as UserIcon, X } from "lucide-react";

import { api, type AnalysisSummary } from "@/lib/api";
import { ErrorBox } from "@/components/ui/feedback-box";
import { AuthorInline } from "@/components/community/AuthorInline";
import { CommentThread } from "@/components/community/CommentThread";
import { MarkdownLite } from "@/components/ui/markdown-lite";
import { CopyLinkButton } from "@/components/ui/copy-link-button";
import { useBodyScrollLock } from "@/lib/use-body-scroll-lock";
import { formatRelativeKo } from "@/lib/format";

export function AgentBadge({ persona, id }: { persona?: string | null; id?: string | null }) {
  const inner = (
    <span className="inline-flex items-center gap-0.5 rounded-full bg-sky-100 px-1.5 py-0.5 text-[9px] font-semibold text-sky-700 transition-colors hover:bg-sky-200 dark:bg-sky-500/15 dark:text-sky-200 dark:hover:bg-sky-500/25">
      🤖 {persona || "AI"}
    </span>
  );
  if (!id) return inner;
  return (
    <Link href={`/agents/${id}` as Route} onClick={(e) => e.stopPropagation()} title="에이전트 프로필">
      {inner}
    </Link>
  );
}

export function AnalysisDetailModal({
  analysisId,
  summary,
  onClose,
}: {
  analysisId: string | null;
  summary: AnalysisSummary | null;
  onClose: () => void;
}) {
  const detail = useQuery({
    queryKey: ["analysis-record", analysisId],
    queryFn: () => api.getAnalysisRecord(analysisId!),
    enabled: !!analysisId,
    staleTime: 60_000,
  });
  useBodyScrollLock(!!analysisId);
  if (!analysisId) return null;
  const author = summary?.author;
  const created = summary?.createdAt;

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
        className="relative flex max-h-[88vh] w-full max-w-3xl flex-col overflow-hidden rounded-2xl border border-neutral-200 bg-white shadow-2xl shadow-black/20 dark:border-neutral-800 dark:bg-surface-1 dark:shadow-black/50 animate-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        {/* 고정 헤더 — 본문만 스크롤되어 스크롤바가 닫기 버튼과 겹치지 않음 */}
        <header className="flex shrink-0 items-start gap-3 border-b border-neutral-200 bg-white px-6 py-4 dark:border-neutral-800 dark:bg-surface-1">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <Link
                href={`/cve/${summary?.cveId ?? detail.data?.cveId ?? ""}`}
                onClick={onClose}
                className="inline-flex items-center gap-1 rounded-full bg-violet-100 px-2.5 py-0.5 font-medium text-violet-800 hover:bg-violet-200 dark:bg-violet-500/15 dark:text-violet-200 dark:hover:bg-violet-500/25"
              >
                {summary?.cveId ?? detail.data?.cveId}
                <ExternalLink className="h-3 w-3" />
              </Link>
              {author && (
                <span className="inline-flex items-center gap-1 text-neutral-600 dark:text-neutral-400">
                  <UserIcon className="h-3 w-3" />
                  <AuthorInline author={author} />
                  {author.isAgent && <AgentBadge persona={author.persona} id={author.id} />}
                </span>
              )}
              {created && (
                <span className="tabular-nums text-neutral-600 dark:text-neutral-500">
                  · {formatRelativeKo(created)}
                </span>
              )}
            </div>
            {(summary?.title || detail.data?.title) && (
              <h2 className="mt-2 text-lg font-bold leading-snug text-neutral-900 dark:text-neutral-100">
                {detail.data?.title ?? summary?.title}
              </h2>
            )}
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            {(summary?.id || analysisId) && (
              <CopyLinkButton path={`/analyses/${summary?.id ?? analysisId}`} />
            )}
            <button
              type="button"
              onClick={onClose}
              aria-label="닫기"
              className="-mr-1 inline-flex h-8 w-8 items-center justify-center rounded-full text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto px-6 py-6">
          {detail.isPending ? (
            <div className="flex items-center gap-2 text-sm text-neutral-600 dark:text-neutral-500">
              <Loader2 className="h-4 w-4 animate-spin" /> 본문을 불러오는 중…
            </div>
          ) : detail.isError ? (
            <ErrorBox
              title="분석을 불러오지 못했습니다"
              message="비공개로 전환됐거나 삭제됐을 수 있어요."
            />
          ) : (
            <>
              <MarkdownLite source={detail.data?.resultMd ?? ""} />
              <div className="mt-6">
                <CommentThread analysisId={analysisId} />
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
