"use client";

/**
 * 커뮤니티 탭 안의 "남이 한 분석" 피드 (PR 10-CN+CO).
 *
 * /community/analyses 는 다른 사용자가 ``public`` 으로 공개한 분석 기록을
 * 시간 역순으로 반환한다. 본인 분석은 자동 제외 (백엔드에서 처리).
 * 각 카드 클릭 시 본문(result_md) 을 펼친 모달로 보여 준다.
 */
import Link from "next/link";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ExternalLink, Loader2, Share2, Sparkles, User as UserIcon, X } from "lucide-react";

import { api, type AnalysisSummary } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { ErrorBox } from "@/components/ui/feedback-box";
import { ShareMyAnalysesModal } from "@/components/community/ShareMyAnalysesModal";
import { formatRelativeKo } from "@/lib/format";

export function AnalysisFeed() {
  const { user } = useAuth();
  const [openId, setOpenId] = useState<string | null>(null);
  const [shareOpen, setShareOpen] = useState(false);
  const list = useQuery({
    queryKey: ["community-analyses"],
    queryFn: () => api.listCommunityAnalyses({ limit: 50 }),
    staleTime: 30_000,
  });

  // 헤더 — 로그인 사용자에겐 "내 분석 공유하기" 버튼 노출. 비로그인은 그대로 읽기만.
  const header = (
    <div className="mb-4 flex flex-wrap items-center justify-between gap-2 text-xs text-neutral-600 dark:text-neutral-500">
      <span>공개된 분석은 시간 역순으로 정렬됩니다.</span>
      {user && (
        <button
          type="button"
          onClick={() => setShareOpen(true)}
          className="inline-flex items-center gap-1.5 rounded-full bg-violet-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-violet-500 dark:bg-violet-500 dark:hover:bg-violet-400"
        >
          <Share2 className="h-3.5 w-3.5" />내 분석 공유하기
        </button>
      )}
    </div>
  );

  if (list.isPending) {
    return (
      <>
        {header}
        <div className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              className="h-24 animate-pulse rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-surface-1/50"
            />
          ))}
        </div>
        <ShareMyAnalysesModal open={shareOpen} onClose={() => setShareOpen(false)} />
      </>
    );
  }
  if (list.isError) {
    return (
      <>
        {header}
        <ErrorBox
          title="분석 피드를 불러오지 못했습니다"
          message="잠시 후 다시 시도해 주세요."
        />
        <ShareMyAnalysesModal open={shareOpen} onClose={() => setShareOpen(false)} />
      </>
    );
  }
  if (!list.data || list.data.items.length === 0) {
    return (
      <>
        {header}
        <div className="rounded-xl border border-neutral-200 bg-white px-6 py-12 text-center dark:border-neutral-800 dark:bg-surface-1">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-violet-500/15 ring-1 ring-violet-400/30">
            <Sparkles className="h-6 w-6 text-violet-700 dark:text-violet-300" />
          </div>
          <h3 className="text-base font-semibold text-neutral-900 dark:text-neutral-100">
            아직 공유된 분석이 없어요
          </h3>
          <p className="mt-1 text-sm text-neutral-700 dark:text-neutral-300">
            CVE 상세에서 AI 심층 분석을 실행한 뒤,{" "}
            {user ? "위의 \"내 분석 공유하기\" 버튼" : "로그인 후 공유 버튼"}으로 골라 공개할 수 있어요.
          </p>
        </div>
        <ShareMyAnalysesModal open={shareOpen} onClose={() => setShareOpen(false)} />
      </>
    );
  }

  return (
    <>
      {header}
      <ul className="space-y-3">
        {list.data.items.map((a) => (
          <li key={a.id}>
            <button
              type="button"
              onClick={() => setOpenId(a.id)}
              className="block w-full rounded-lg border border-neutral-200 bg-white p-4 text-left transition-all duration-150 hover:-translate-y-0.5 hover:border-violet-300 hover:shadow-md hover:shadow-violet-900/5 active:translate-y-0 dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-violet-500/40"
            >
              <div className="flex flex-wrap items-baseline gap-x-2 text-xs">
                <span className="rounded-full bg-violet-100 px-2 py-0.5 font-medium text-violet-800 dark:bg-violet-500/15 dark:text-violet-200">
                  {a.cveId}
                </span>
                <span className="text-neutral-500 dark:text-neutral-500">·</span>
                <span className="font-medium text-neutral-800 dark:text-neutral-200">
                  {a.author.nickname || a.author.username}
                </span>
                <span className="text-neutral-500 dark:text-neutral-500">·</span>
                <span className="tabular-nums text-neutral-600 dark:text-neutral-500">
                  {formatRelativeKo(a.createdAt)}
                </span>
                {a.category && a.category !== "general" && (
                  <>
                    <span className="text-neutral-500 dark:text-neutral-500">·</span>
                    <span className="rounded-full bg-neutral-100 px-2 py-0.5 text-neutral-700 dark:bg-surface-2 dark:text-neutral-300">
                      {a.category}
                    </span>
                  </>
                )}
              </div>
              {a.title && (
                <h3 className="mt-2 text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                  {a.title}
                </h3>
              )}
              <p className="mt-1.5 line-clamp-2 text-xs leading-relaxed text-neutral-700 dark:text-neutral-400">
                {a.excerpt}
              </p>
            </button>
          </li>
        ))}
      </ul>
      <AnalysisDetailModal
        analysisId={openId}
        summary={list.data.items.find((a) => a.id === openId) ?? null}
        onClose={() => setOpenId(null)}
      />
      <ShareMyAnalysesModal open={shareOpen} onClose={() => setShareOpen(false)} />
    </>
  );
}

function AnalysisDetailModal({
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
        className="relative w-full max-w-3xl rounded-2xl border border-neutral-200 bg-white shadow-2xl shadow-black/20 dark:border-neutral-800 dark:bg-surface-1 dark:shadow-black/50 animate-in zoom-in-95 duration-150"
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

        <article className="px-6 py-7">
          <header className="mb-4 border-b border-neutral-200 pb-4 pr-10 dark:border-neutral-800">
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
                  {author.nickname || author.username}
                </span>
              )}
              {created && (
                <span className="tabular-nums text-neutral-600 dark:text-neutral-500">
                  · {formatRelativeKo(created)}
                </span>
              )}
            </div>
            {(summary?.title || detail.data?.title) && (
              <h2 className="mt-2 text-lg font-bold text-neutral-900 dark:text-neutral-100">
                {detail.data?.title ?? summary?.title}
              </h2>
            )}
          </header>

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
            <div className="prose prose-sm max-w-none whitespace-pre-wrap break-words text-sm leading-relaxed text-neutral-800 dark:prose-invert dark:text-neutral-200">
              {detail.data?.resultMd}
            </div>
          )}
        </article>
      </div>
    </div>
  );
}
