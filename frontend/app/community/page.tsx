"use client";

import { useState } from "react";
import Link from "next/link";
import type { Route } from "next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, Hash, Heart, Loader2, LogIn, MessageSquare, Plus, RefreshCw, Sparkles, Trash2 } from "lucide-react";

import { api, type CommunityPost, type PostListResponse } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { Button } from "@/components/ui/button";
import { ErrorBox, FeedbackBoxButton } from "@/components/ui/feedback-box";
import { NewPostModal } from "@/components/community/NewPostModal";
import { PostModal } from "@/components/community/PostModal";
import { formatRelativeKo, stripMarkdown } from "@/lib/format";
import { cn } from "@/lib/utils";

// 작성자 이름 기반 결정적 아바타 색상 — 피드에서 작성자 구분이 쉽게.
const AVATAR_TONES = [
  "bg-sky-100 text-sky-700 dark:bg-sky-500/15 dark:text-sky-300",
  "bg-violet-100 text-violet-700 dark:bg-violet-500/15 dark:text-violet-300",
  "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300",
  "bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-300",
  "bg-rose-100 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300",
  "bg-cyan-100 text-cyan-700 dark:bg-cyan-500/15 dark:text-cyan-300",
];
function avatarTone(name: string): string {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return AVATAR_TONES[h % AVATAR_TONES.length];
}

export default function CommunityPage() {
  const { user } = useAuth();
  const qc = useQueryClient();
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState(false);
  const [deletingId, setDeletingId] = useState<number | null>(null);
  // null = no post open. Set to post.id when user clicks a feed row.
  // Keeps scroll position + pagination intact.
  const [openPostId, setOpenPostId] = useState<number | null>(null);

  const requireLogin = (): boolean => {
    if (user) return true;
    if (typeof window !== "undefined") {
      const next = window.location.pathname + window.location.search;
      window.location.href = `/login?next=${encodeURIComponent(next)}`;
    }
    return false;
  };
  // 새 글 작성 진입 — 비로그인이면 /login 우회.
  const openNewPost = () => {
    if (requireLogin()) setOpen(true);
  };

  const { data, isPending, isError, refetch } = useQuery({
    queryKey: ["community-posts", page],
    queryFn: () => api.listPosts(page, 20),
    staleTime: 10_000,
  });

  // 글 목록 카드 자체에서 빠르게 삭제 — owner / admin 모두 사용.
  const deletePost = useMutation({
    mutationFn: (id: number) => api.deletePost(id),
    onMutate: (id) => setDeletingId(id),
    onSettled: () => setDeletingId(null),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["community-posts"] }),
  });

  // 좋아요 인라인 토글 — 현재 페이지의 목록 쿼리에 낙관적 반영 후 정합화.
  const like = useMutation({
    mutationFn: ({ id, next }: { id: number; next: boolean }) =>
      next ? api.likePost(id) : api.unlikePost(id),
    onMutate: async ({ id, next }) => {
      await qc.cancelQueries({ queryKey: ["community-posts", page] });
      const prev = qc.getQueryData<PostListResponse>(["community-posts", page]);
      if (prev) {
        qc.setQueryData<PostListResponse>(["community-posts", page], {
          ...prev,
          items: prev.items.map((p) =>
            p.id === id
              ? {
                  ...p,
                  isLiked: next,
                  likeCount: next
                    ? p.likeCount + (p.isLiked ? 0 : 1)
                    : Math.max(0, p.likeCount - (p.isLiked ? 1 : 0)),
                }
              : p,
          ),
        });
      }
      return { prev };
    },
    onError: (_e, _v, ctx) => {
      if (ctx?.prev) qc.setQueryData(["community-posts", page], ctx.prev);
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ["community-posts"] }),
  });
  const toggleLike = (p: CommunityPost) => {
    if (!requireLogin()) return;
    like.mutate({ id: p.id, next: !p.isLiked });
  };

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.pageSize)) : 1;

  return (
    <div className="mx-auto min-h-[calc(100vh-3.5rem)] max-w-2xl px-4 py-8 sm:px-6 sm:py-10">
      <header className="mb-6 flex flex-wrap items-end justify-between gap-3 border-b border-neutral-200 pb-4 dark:border-neutral-800">
        <div>
          <h1 className="text-2xl font-bold text-neutral-900 dark:text-neutral-100">커뮤니티</h1>
          <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-500">
            보안 운영자들의 글을 타임라인으로 확인하세요.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {user ? (
            <Button onClick={openNewPost} size="sm" className="gap-2">
              <Plus className="h-4 w-4" />새 글
            </Button>
          ) : (
            <Button onClick={openNewPost} variant="outline" size="sm" className="gap-2">
              <LogIn className="h-4 w-4" />
              로그인 후 작성
            </Button>
          )}
        </div>
      </header>

      {isPending ? (
        <div className="overflow-hidden rounded-xl border border-neutral-200 dark:border-neutral-800">
          {Array.from({ length: 5 }).map((_, i) => (
            <div
              key={i}
              className="flex gap-3 border-b border-neutral-200 p-4 last:border-b-0 dark:border-neutral-800"
            >
              <div className="h-10 w-10 shrink-0 animate-pulse rounded-full bg-neutral-100 dark:bg-surface-2" />
              <div className="flex-1 space-y-2">
                <div className="h-3 w-32 animate-pulse rounded bg-neutral-100 dark:bg-surface-2" />
                <div className="h-3 w-full animate-pulse rounded bg-neutral-100 dark:bg-surface-2" />
                <div className="h-3 w-2/3 animate-pulse rounded bg-neutral-100 dark:bg-surface-2" />
              </div>
            </div>
          ))}
        </div>
      ) : isError ? (
        <ErrorBox
          title="글 목록을 불러오지 못했습니다"
          message="잠시 후 다시 시도하거나 백엔드 상태를 확인해 보세요."
          actions={
            <FeedbackBoxButton onClick={() => refetch()}>
              <RefreshCw className="h-3 w-3" />
              다시 시도
            </FeedbackBoxButton>
          }
        />
      ) : data && data.items.length === 0 ? (
        <div className="rounded-xl border border-neutral-200 bg-white px-6 py-12 text-center dark:border-neutral-800 dark:bg-surface-1">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-sky-500/15 ring-1 ring-sky-400/30">
            <Sparkles className="h-6 w-6 text-sky-700 dark:text-sky-300" />
          </div>
          <h3 className="text-base font-semibold text-neutral-900 dark:text-neutral-100">
            첫 번째 글의 주인공이 되어보세요
          </h3>
          <p className="mt-1 text-sm text-neutral-700 dark:text-neutral-300">
            CVE 분석, 완화 방안, 실전 사례 — 어떤 주제든 공유해 주세요.
          </p>
          <Button onClick={openNewPost} className="mt-5 gap-2" variant={user ? "default" : "outline"}>
            {user ? <Plus className="h-4 w-4" /> : <LogIn className="h-4 w-4" />}
            {user ? "첫 글 작성하기" : "로그인하고 첫 글 작성하기"}
          </Button>
        </div>
      ) : (
        <ul className="space-y-3">
          {data?.items.map((p) => (
            <li
              key={p.id}
              className="group rounded-2xl border border-neutral-200 bg-white transition-all hover:border-neutral-300 hover:shadow-sm dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-neutral-700"
            >
              <article className="flex gap-3 p-4 sm:gap-4 sm:p-5">
                {/* 아바타 — authorName 이니셜 원형(이름별 색상) */}
                <span
                  className={cn(
                    "flex h-11 w-11 shrink-0 items-center justify-center rounded-full text-base font-bold",
                    avatarTone(p.authorName),
                  )}
                >
                  {(p.authorName.trim().charAt(0) || "?").toUpperCase()}
                </span>

                <div className="min-w-0 flex-1">
                  {/* 본문 — 클릭 시 상세 모달 */}
                  <button
                    type="button"
                    onClick={() => setOpenPostId(p.id)}
                    className="block w-full text-left"
                  >
                    <div className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-sm">
                      <span className="font-semibold text-neutral-900 dark:text-neutral-100">
                        {p.authorName}
                      </span>
                      <span className="text-neutral-400 dark:text-neutral-600">·</span>
                      <span className="tabular-nums text-xs text-neutral-500 dark:text-neutral-500">
                        {formatRelativeKo(p.createdAt)}
                      </span>
                    </div>
                    {p.title && (
                      <h3 className="mt-1 text-[15px] font-semibold leading-snug text-neutral-900 dark:text-neutral-100">
                        {p.title}
                      </h3>
                    )}
                    <p className="mt-1 line-clamp-3 whitespace-pre-line text-sm leading-relaxed text-neutral-600 dark:text-neutral-400">
                      {stripMarkdown(p.content)}
                    </p>
                  </button>

                  {/* 연결된 CVE 태그 — 클릭 시 해당 CVE 로 이동 */}
                  {(p.cveId || p.vulnerabilityId) && (
                    <div className="mt-2">
                      {p.cveId ? (
                        <Link
                          href={`/cve/${p.cveId}` as Route}
                          onClick={(e) => e.stopPropagation()}
                          className="inline-flex items-center gap-1 rounded-full bg-sky-50 px-2 py-0.5 font-mono text-[11px] font-medium text-sky-700 ring-1 ring-inset ring-sky-200 transition-colors hover:bg-sky-100 dark:bg-sky-500/10 dark:text-sky-300 dark:ring-sky-500/30 dark:hover:bg-sky-500/20"
                        >
                          <Hash className="h-3 w-3" />
                          {p.cveId}
                        </Link>
                      ) : null}
                    </div>
                  )}

                  {/* 액션 바 — 댓글 / 좋아요 / 조회 (+ 관리 삭제) */}
                  <div className="mt-3 flex items-center gap-1 text-neutral-500 dark:text-neutral-500">
                    <button
                      type="button"
                      onClick={() => setOpenPostId(p.id)}
                      className="group/btn inline-flex items-center gap-1.5 rounded-full px-2 py-1 text-xs transition-colors hover:bg-sky-50 hover:text-sky-600 dark:hover:bg-sky-500/10 dark:hover:text-sky-300"
                      title="댓글"
                    >
                      <MessageSquare className="h-4 w-4" />
                      <span className="tabular-nums">{p.commentCount}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => toggleLike(p)}
                      aria-pressed={p.isLiked}
                      className={cn(
                        "inline-flex items-center gap-1.5 rounded-full px-2 py-1 text-xs transition-colors hover:bg-rose-50 hover:text-rose-600 dark:hover:bg-rose-500/10 dark:hover:text-rose-300",
                        p.isLiked && "text-rose-600 dark:text-rose-400",
                      )}
                      title={p.isLiked ? "좋아요 취소" : "좋아요"}
                    >
                      <Heart className={cn("h-4 w-4", p.isLiked && "fill-current")} />
                      <span className="tabular-nums">{p.likeCount}</span>
                    </button>
                    <span
                      className="inline-flex items-center gap-1.5 px-2 py-1 text-xs"
                      title="조회수"
                    >
                      <Eye className="h-4 w-4" />
                      <span className="tabular-nums">{p.viewCount}</span>
                    </span>
                    {p.canManage && (
                      <button
                        type="button"
                        disabled={deletePost.isPending && deletingId === p.id}
                        onClick={() => {
                          const msg = p.isOwner
                            ? "이 글을 삭제할까요?"
                            : "관리자 권한으로 이 글을 삭제할까요?";
                          if (confirm(msg)) deletePost.mutate(p.id);
                        }}
                        title={p.isOwner ? "삭제" : "관리자 권한으로 삭제"}
                        className="ml-auto inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs text-neutral-400 opacity-0 transition-opacity hover:bg-red-50 hover:text-red-600 group-hover:opacity-100 disabled:opacity-50 dark:hover:bg-red-950/40 dark:hover:text-red-300"
                      >
                        {deletePost.isPending && deletingId === p.id ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Trash2 className="h-3.5 w-3.5" />
                        )}
                      </button>
                    )}
                  </div>
                </div>
              </article>
            </li>
          ))}
        </ul>
      )}

      {data && data.total > data.pageSize && (
        <div className="mt-6 flex items-center justify-center gap-2 text-sm">
          <Button
            variant="outline"
            size="sm"
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            이전
          </Button>
          <span className="tabular-nums text-neutral-600 dark:text-neutral-500">
            {page} / {totalPages}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={page >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
          >
            다음
          </Button>
        </div>
      )}

      <NewPostModal open={open} onClose={() => setOpen(false)} />
      <PostModal postId={openPostId} onClose={() => setOpenPostId(null)} />
    </div>
  );
}
