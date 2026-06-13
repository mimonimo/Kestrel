"use client";

/**
 * PostModal — PR 10-DB UI 개선:
 *  - 헤더 우측에 좋아요·수정·삭제 액션 (이전엔 본문 아래에 삭제만).
 *  - 인라인 수정 모드 (title + content 편집 → 저장/취소).
 *  - 좋아요 토글 — 비로그인은 /login 우회.
 */
import Link from "next/link";
import type { Route } from "next";
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Edit3,
  ExternalLink,
  Eye,
  Heart,
  Loader2,
  MessageSquare,
  Save,
  Trash2,
  X,
} from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { Button } from "@/components/ui/button";
import { ErrorBox } from "@/components/ui/feedback-box";
import { Input } from "@/components/ui/input";
import { CommentThread } from "@/components/community/CommentThread";
import { MarkdownLite } from "@/components/ui/markdown-lite";
import { formatRelativeKo } from "@/lib/format";
import { useBodyScrollLock } from "@/lib/use-body-scroll-lock";
import { cn } from "@/lib/utils";

interface Props {
  postId: number | null;
  onClose: () => void;
}

export function PostModal({ postId, onClose }: Props) {
  const qc = useQueryClient();
  const { user } = useAuth();
  const open = postId != null;
  useBodyScrollLock(open);

  const { data, isPending, isError } = useQuery({
    queryKey: ["community-post", postId],
    queryFn: () => api.getPost(postId!),
    enabled: open,
    staleTime: 5_000,
  });

  // ── 수정 모드 ────────────────────────────────────────
  const [editing, setEditing] = useState(false);
  const [draftTitle, setDraftTitle] = useState("");
  const [draftContent, setDraftContent] = useState("");
  const [editError, setEditError] = useState<string | null>(null);

  useEffect(() => {
    if (data) {
      setDraftTitle(data.title);
      setDraftContent(data.content);
    }
    setEditing(false);
  }, [data?.id]);

  const update = useMutation({
    mutationFn: () =>
      api.updatePost(postId!, {
        title: draftTitle.trim(),
        content: draftContent.trim(),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["community-post", postId] });
      qc.invalidateQueries({ queryKey: ["community-posts"] });
      setEditing(false);
      setEditError(null);
    },
    onError: (e) =>
      setEditError(e instanceof ApiError ? e.message : "수정에 실패했어요."),
  });

  const remove = useMutation({
    mutationFn: () => api.deletePost(postId!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["community-posts"] });
      qc.invalidateQueries({ queryKey: ["community-post", postId] });
      onClose();
    },
  });

  // ── 좋아요 ────────────────────────────────────────────
  const like = useMutation({
    mutationFn: (next: boolean) =>
      next ? api.likePost(postId!) : api.unlikePost(postId!),
    onMutate: async (next) => {
      await qc.cancelQueries({ queryKey: ["community-post", postId] });
      const prev = qc.getQueryData<typeof data>(["community-post", postId]);
      if (prev) {
        qc.setQueryData(["community-post", postId], {
          ...prev,
          isLiked: next,
          likeCount: next
            ? prev.likeCount + (prev.isLiked ? 0 : 1)
            : Math.max(0, prev.likeCount - (prev.isLiked ? 1 : 0)),
        });
      }
      return { prev };
    },
    onError: (_e, _next, ctx) => {
      if (ctx?.prev) qc.setQueryData(["community-post", postId], ctx.prev);
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ["community-post", postId] });
      qc.invalidateQueries({ queryKey: ["community-posts"] });
    },
  });

  const toggleLike = () => {
    if (!user) {
      if (typeof window !== "undefined") {
        const next = window.location.pathname + window.location.search;
        window.location.href = `/login?next=${encodeURIComponent(next)}`;
      }
      return;
    }
    if (!data) return;
    like.mutate(!data.isLiked);
  };

  // ── ESC 닫기 (스크롤 잠금은 useBodyScrollLock 가 담당) ──
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !editing) onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
    };
  }, [open, onClose, editing]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="post-modal-title"
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-neutral-950/60 px-4 py-10 backdrop-blur-sm animate-in fade-in duration-150"
      onClick={(e) => {
        if (e.target === e.currentTarget && !editing) onClose();
      }}
    >
      <div
        className="relative w-full max-w-3xl rounded-2xl border border-neutral-200 bg-white shadow-2xl shadow-black/20 dark:border-neutral-800 dark:bg-surface-1 dark:shadow-black/50 animate-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        {isPending ? (
          // 회색 큰 박스만 띄우지 말고 실제 헤더/본문 구조의 skeleton 으로
          // 보여서 깜빡임 줄이기.
          <>
            <button
              type="button"
              onClick={onClose}
              aria-label="닫기"
              className="absolute right-3 top-3 z-10 inline-flex h-8 w-8 items-center justify-center rounded-full text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
            >
              <X className="h-4 w-4" />
            </button>
            <header className="flex items-start justify-between gap-3 border-b border-neutral-200 px-6 py-4 dark:border-neutral-800">
              <div className="min-w-0 flex-1 space-y-2">
                <div className="h-5 w-2/3 animate-pulse rounded bg-neutral-200 dark:bg-surface-2" />
                <div className="h-3 w-1/2 animate-pulse rounded bg-neutral-200 dark:bg-surface-2" />
              </div>
            </header>
            <div className="space-y-2 px-6 py-5">
              {Array.from({ length: 6 }).map((_, i) => (
                <div
                  key={i}
                  className={cn(
                    "h-3 animate-pulse rounded bg-neutral-200 dark:bg-surface-2",
                    i % 3 === 2 ? "w-4/5" : "w-full",
                  )}
                />
              ))}
              <div className="mt-4 flex items-center gap-2 text-xs text-neutral-600 dark:text-neutral-400">
                <Loader2 className="h-3.5 w-3.5 animate-spin" /> 글을 불러오는 중…
              </div>
            </div>
          </>
        ) : isError || !data ? (
          <div className="p-6">
            <button
              type="button"
              onClick={onClose}
              aria-label="닫기"
              className="absolute right-3 top-3 z-10 inline-flex h-8 w-8 items-center justify-center rounded-full text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
            >
              <X className="h-4 w-4" />
            </button>
            <ErrorBox
              title="글을 불러오지 못했습니다"
              message="잠시 후 다시 시도하거나 백엔드 상태를 확인해 보세요."
            />
          </div>
        ) : (
          <article>
            {/* ── 헤더: 메타 + 액션 ─────────────────────── */}
            <header className="flex items-start justify-between gap-3 border-b border-neutral-200 px-6 py-4 dark:border-neutral-800">
              <div className="min-w-0 flex-1">
                {editing ? (
                  <Input
                    value={draftTitle}
                    onChange={(e) => setDraftTitle(e.target.value)}
                    maxLength={255}
                    className="text-lg font-bold"
                    autoFocus
                  />
                ) : (
                  <h2
                    id="post-modal-title"
                    className="text-xl font-bold text-neutral-900 dark:text-neutral-100"
                  >
                    {data.title}
                  </h2>
                )}
                <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-neutral-600 dark:text-neutral-500">
                  <span className="font-medium text-neutral-800 dark:text-neutral-300">
                    {data.authorName}
                  </span>
                  <span>·</span>
                  <span className="tabular-nums">{formatRelativeKo(data.createdAt)}</span>
                  <span>·</span>
                  <span className="inline-flex items-center gap-1 tabular-nums">
                    <Eye className="h-3 w-3" />
                    {data.viewCount}
                  </span>
                  <span>·</span>
                  <span className="inline-flex items-center gap-1 tabular-nums">
                    <MessageSquare className="h-3 w-3" />
                    {data.commentCount}
                  </span>
                  {data.cveId && (
                    <Link
                      href={`/cve/${data.cveId}` as Route}
                      onClick={onClose}
                      className="inline-flex items-center gap-1 rounded-full bg-sky-100 px-2 py-0.5 font-mono text-sky-800 hover:bg-sky-200 dark:bg-sky-500/15 dark:text-sky-200 dark:hover:bg-sky-600/25"
                    >
                      <ExternalLink className="h-3 w-3" />
                      {data.cveId}
                    </Link>
                  )}
                </div>
              </div>

              {/* 헤더 우측 액션 — 모바일에서 라벨은 숨기고 아이콘만, sm+ 에서 라벨 노출 */}
              <div className="flex shrink-0 items-center gap-1 sm:gap-1.5">
                {/* 좋아요 — 비로그인은 클릭 시 /login */}
                <button
                  type="button"
                  onClick={toggleLike}
                  disabled={like.isPending}
                  title={data.isLiked ? "좋아요 취소" : "좋아요"}
                  className={cn(
                    "inline-flex h-8 items-center gap-1 rounded-full border px-2 text-xs font-medium transition-colors sm:px-2.5",
                    data.isLiked
                      ? "border-rose-300 bg-rose-50 text-rose-700 hover:bg-rose-100 dark:border-rose-500/40 dark:bg-rose-500/15 dark:text-rose-200"
                      : "border-neutral-300 text-neutral-700 hover:border-rose-300 hover:text-rose-700 dark:border-neutral-700 dark:text-neutral-300 dark:hover:border-rose-500/40 dark:hover:text-rose-200",
                    "disabled:opacity-50",
                  )}
                >
                  <Heart
                    className={cn("h-3.5 w-3.5", data.isLiked && "fill-current")}
                  />
                  <span className="tabular-nums">{data.likeCount}</span>
                </button>

                {/* 수정 — owner 또는 admin */}
                {data.canManage && !editing && (
                  <button
                    type="button"
                    onClick={() => setEditing(true)}
                    title={data.isOwner ? "수정" : "관리자 권한으로 수정"}
                    aria-label="수정"
                    className="inline-flex h-8 items-center gap-1 rounded-full border border-neutral-300 px-2 text-xs font-medium text-neutral-700 transition-colors hover:border-sky-300 hover:text-sky-700 sm:px-2.5 dark:border-neutral-700 dark:text-neutral-300 dark:hover:border-sky-500/40 dark:hover:text-sky-200"
                  >
                    <Edit3 className="h-3.5 w-3.5" />
                    <span className="hidden sm:inline">수정</span>
                  </button>
                )}

                {/* 삭제 — owner 또는 admin */}
                {data.canManage && !editing && (
                  <button
                    type="button"
                    onClick={() => {
                      const msg = data.isOwner
                        ? "이 글을 삭제하시겠습니까?"
                        : "관리자 권한으로 이 글을 삭제하시겠습니까?";
                      if (confirm(msg)) remove.mutate();
                    }}
                    disabled={remove.isPending}
                    title={data.isOwner ? "삭제" : "관리자 권한으로 삭제"}
                    aria-label="삭제"
                    className="inline-flex h-8 items-center gap-1 rounded-full border border-red-300 px-2 text-xs font-medium text-red-700 transition-colors hover:bg-red-50 disabled:opacity-50 sm:px-2.5 dark:border-red-900/50 dark:text-red-300 dark:hover:bg-red-950/40"
                  >
                    {remove.isPending ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Trash2 className="h-3.5 w-3.5" />
                    )}
                    <span className="hidden sm:inline">삭제</span>
                  </button>
                )}

                {!data.isOwner && data.canManage && !editing && (
                  <span className="hidden h-8 items-center gap-1 rounded-full bg-amber-100 px-2 text-[11px] font-medium text-amber-800 sm:inline-flex dark:bg-amber-500/15 dark:text-amber-200">
                    관리자
                  </span>
                )}

                <button
                  type="button"
                  onClick={onClose}
                  aria-label="닫기"
                  className="inline-flex h-8 w-8 items-center justify-center rounded-full text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </header>

            {/* ── 본문 ─────────────────────────────────── */}
            <div className="px-6 py-5">
              {editing ? (
                <>
                  <textarea
                    value={draftContent}
                    onChange={(e) => setDraftContent(e.target.value)}
                    className="block min-h-[280px] w-full resize-y rounded-lg border border-neutral-300 bg-white p-3 text-sm leading-relaxed text-neutral-900 placeholder:text-neutral-400 focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-200 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100 dark:focus:ring-sky-500/30"
                    maxLength={20000}
                  />
                  {editError && (
                    <p className="mt-2 text-xs text-rose-700 dark:text-rose-300">
                      {editError}
                    </p>
                  )}
                  <div className="mt-3 flex items-center justify-end gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setEditing(false);
                        setDraftTitle(data.title);
                        setDraftContent(data.content);
                        setEditError(null);
                      }}
                      disabled={update.isPending}
                    >
                      취소
                    </Button>
                    <Button
                      type="button"
                      size="sm"
                      onClick={() => {
                        if (!draftTitle.trim() || !draftContent.trim()) {
                          setEditError("제목과 본문은 비울 수 없어요.");
                          return;
                        }
                        update.mutate();
                      }}
                      disabled={update.isPending}
                      className="gap-1 bg-sky-500 text-white hover:bg-sky-600 disabled:opacity-50 dark:bg-sky-500 dark:hover:bg-sky-400"
                    >
                      {update.isPending ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Save className="h-3.5 w-3.5" />
                      )}
                      저장
                    </Button>
                  </div>
                </>
              ) : (
                <MarkdownLite source={data.content} />
              )}
            </div>

            {!editing && <CommentThread postId={data.id} />}
          </article>
        )}
      </div>
    </div>
  );
}
