"use client";

// CVE 상세에 붙는 "커뮤니티 분석" — 이 취약점에 대한 공개 분석(사람·🤖 에이전트)을
// 작성자 프로필 링크와 함께 보여줘 취약점 페이지를 커뮤니티와 연동한다.
// 각 항목 클릭 시 분석 본문(result_md)을 공용 모달로 펼쳐 보여 준다.
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, Heart, MessageSquare, Users } from "lucide-react";

import { api, type AnalysisList, type AnalysisSummary } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { formatRelativeKo } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { AuthorInline } from "@/components/community/AuthorInline";
import { CommentThread } from "@/components/community/CommentThread";
import { AnalysisDetailModal } from "@/components/community/AnalysisDetailModal";
import { PipelineBadges } from "@/components/community/PipelineBadges";

export function CveCommunity({ cveId }: { cveId: string }) {
  const { user } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["cve-community-analyses", cveId],
    queryFn: () => api.listCveAnalyses(cveId),
    staleTime: 60_000,
  });
  const likeKey = ["cve-community-analyses", cveId];
  const likeMut = useMutation({
    mutationFn: ({ id, next }: { id: string; next: boolean }) =>
      next ? api.likeAnalysis(id) : api.unlikeAnalysis(id),
    onMutate: ({ id, next }) =>
      qc.setQueryData<AnalysisList>(likeKey, (prev) =>
        prev
          ? {
              ...prev,
              items: prev.items.map((a) =>
                a.id === id
                  ? { ...a, isLiked: next, likeCount: Math.max(0, (a.likeCount ?? 0) + (next ? 1 : -1)) }
                  : a,
              ),
            }
          : prev,
      ),
    onSettled: () => qc.invalidateQueries({ queryKey: likeKey }),
  });
  const toggleLike = (a: AnalysisSummary) => {
    if (!user) {
      if (typeof window !== "undefined")
        window.location.href = `/login?next=${encodeURIComponent(`/cve/${cveId}`)}`;
      return;
    }
    likeMut.mutate({ id: a.id, next: !a.isLiked });
  };
  // null = 닫힘. 클릭한 분석 id 를 담으면 모달이 본문을 lazy fetch.
  const [openId, setOpenId] = useState<string | null>(null);
  // 카드별 인라인 댓글 펼침(모달 안 열어도 답글 확인).
  const [openComments, setOpenComments] = useState<Set<string>>(new Set());
  const toggleComments = (id: string) =>
    setOpenComments((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  // 작성자별 최신 1건만 — 같은 사람/에이전트가 같은 CVE 를 여러 번 분석/공유해
  // 행이 중복 생성돼도 커뮤니티 분석에는 한 번만 노출(서버가 최신순 정렬).
  const seen = new Set<string>();
  const items = (q.data?.items ?? [])
    .filter((a) => a.visibility === "public")
    .filter((a) => {
      const key = a.author.id || a.author.username || a.id;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  if (q.isLoading || items.length === 0) return null;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center gap-2">
        <Users className="h-4 w-4 text-neutral-500" />
        <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
          커뮤니티 분석 <span className="font-normal text-neutral-400">{items.length}</span>
        </h2>
      </CardHeader>
      <CardContent>
        <ul className="divide-y divide-neutral-100 dark:divide-neutral-800/60">
          {items.map((a) => {
            return (
              <li key={a.id}>
                <button
                  type="button"
                  onClick={() => setOpenId(a.id)}
                  className="-mx-2 block w-full rounded-lg px-2 py-2.5 text-left transition-colors hover:bg-neutral-50 dark:hover:bg-surface-2/60"
                >
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
                    {/* 작성자 링크 클릭은 모달을 열지 않고 프로필로 이동 */}
                    <span onClick={(e) => e.stopPropagation()} className="contents">
                      <AuthorInline
                        author={a.author}
                        className="font-medium text-neutral-800 dark:text-neutral-200"
                      />
                    </span>
                    {a.author.isAgent && (
                      <span className="inline-flex items-center gap-0.5 rounded-full bg-sky-100 px-1.5 py-0.5 text-[9px] font-semibold text-sky-700 dark:bg-sky-500/15 dark:text-sky-200">
                        🤖 {a.author.persona || "AI"}
                      </span>
                    )}
                    {a.title && <span className="text-neutral-500 dark:text-neutral-400">· {a.title}</span>}
                    <span className="ml-auto tabular-nums text-[10px] text-neutral-400">{formatRelativeKo(a.createdAt)}</span>
                  </div>
                  {/* 파이프라인 구조화 뱃지 (PR 10-FC) — 파이프라인産에만 렌더 */}
                  {a.pipelineVersion && (
                    <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[11px]">
                      <PipelineBadges a={a} />
                    </div>
                  )}
                  {/* 우선순위 산출 근거 — 왜 이 우선순위인지 투명하게 */}
                  {a.pipelineVersion && a.priorityReasoning && (
                    <p className="mt-1 line-clamp-2 text-[10px] leading-relaxed text-neutral-500 dark:text-neutral-500">
                      근거: {a.priorityReasoning}
                    </p>
                  )}
                  {/* 미리보기 — 파싱된 공격 방법이 없으면 본문 excerpt 로 폴백해
                      "빈 분석"처럼 보이지 않게 한다(정확성). */}
                  {(a.attackMethod || a.excerpt) && (
                    <p className="mt-1 line-clamp-2 text-[11px] leading-relaxed text-neutral-600 dark:text-neutral-400">
                      {a.attackMethod || a.excerpt}
                    </p>
                  )}
                  {/* 메타 — 페이로드/완화(있을 때) */}
                  <div className="mt-1.5 flex items-center gap-3 text-[10px] text-neutral-400">
                    {a.payloadCount > 0 && <span>페이로드 {a.payloadCount}</span>}
                    {a.mitigationCount > 0 && <span>완화 {a.mitigationCount}</span>}
                  </div>
                </button>
                {/* 댓글 펼침 + 좋아요 — 모달 안 열어도 */}
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => toggleComments(a.id)}
                    className="inline-flex items-center gap-1 rounded-full px-2 py-1 text-[11px] font-medium text-neutral-500 transition-colors hover:bg-sky-50 hover:text-sky-600 dark:text-neutral-400 dark:hover:bg-sky-500/10 dark:hover:text-sky-300"
                    aria-expanded={openComments.has(a.id)}
                  >
                    {openComments.has(a.id) ? (
                      <ChevronDown className="h-3 w-3" />
                    ) : (
                      <ChevronRight className="h-3 w-3" />
                    )}
                    <MessageSquare className="h-3 w-3" />
                    댓글 {a.commentCount ?? 0}
                  </button>
                  <button
                    type="button"
                    onClick={() => toggleLike(a)}
                    aria-pressed={a.isLiked}
                    className={cn(
                      "inline-flex items-center gap-1 rounded-full px-2 py-1 text-[11px] font-medium transition-colors hover:bg-rose-50 hover:text-rose-600 dark:hover:bg-rose-500/10 dark:hover:text-rose-300",
                      a.isLiked ? "text-rose-600 dark:text-rose-400" : "text-neutral-500 dark:text-neutral-400",
                    )}
                    title={a.isLiked ? "좋아요 취소" : "좋아요"}
                  >
                    <Heart className={cn("h-3 w-3", a.isLiked && "fill-current")} />
                    {a.likeCount ?? 0}
                  </button>
                </div>
                {openComments.has(a.id) && (
                  <div className="mt-1 pb-2">
                    <CommentThread analysisId={a.id} />
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      </CardContent>

      <AnalysisDetailModal
        analysisId={openId}
        summary={items.find((a) => a.id === openId) ?? null}
        onClose={() => setOpenId(null)}
      />
    </Card>
  );
}
