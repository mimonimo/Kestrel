"use client";

import Link from "next/link";
import { useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, ExternalLink, MessageSquare, Trash2, X } from "lucide-react";

import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { ErrorBox } from "@/components/ui/feedback-box";
import { CommentThread } from "@/components/community/CommentThread";
import { formatRelativeKo } from "@/lib/format";

interface Props {
  postId: number | null;
  onClose: () => void;
}

// Centered overlay that lets the user read a post + comment thread
// without leaving the list. Replaces the previous /community/[id] route
// for inline browsing — that page still works as a sharable deep link,
// but the typical list → read flow now stays on /community so scroll
// position and pagination are preserved.
export function PostModal({ postId, onClose }: Props) {
  const qc = useQueryClient();
  const open = postId != null;

  const { data, isPending, isError } = useQuery({
    queryKey: ["community-post", postId],
    queryFn: () => api.getPost(postId!),
    enabled: open,
    staleTime: 5_000,
  });

  const remove = useMutation({
    mutationFn: () => api.deletePost(postId!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["community-posts"] });
      qc.invalidateQueries({ queryKey: ["community-post", postId] });
      onClose();
    },
  });

  // ESC closes; body scroll lock while open so backdrop scroll doesn't
  // bleed through. Restoring overflow on unmount handles fast close.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="post-modal-title"
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-neutral-950/60 px-4 py-10 backdrop-blur-sm animate-in fade-in duration-150"
      onClick={(e) => {
        // Backdrop click → close. Inner card stops propagation.
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="relative w-full max-w-3xl rounded-2xl border border-neutral-200 bg-white shadow-2xl shadow-black/20 dark:border-neutral-800 dark:bg-surface-1 dark:shadow-black/50 animate-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Close button — top-right, rounded-full icon-only */}
        <button
          type="button"
          onClick={onClose}
          aria-label="닫기"
          className="absolute right-3 top-3 z-10 inline-flex h-8 w-8 items-center justify-center rounded-full text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
        >
          <X className="h-4 w-4" />
        </button>

        {isPending ? (
          <div className="h-72 animate-pulse rounded-2xl bg-neutral-100 dark:bg-surface-2" />
        ) : isError || !data ? (
          <div className="p-6">
            <ErrorBox
              title="글을 불러오지 못했습니다"
              message="잠시 후 다시 시도하거나 백엔드 상태를 확인해 보세요."
            />
          </div>
        ) : (
          <article className="px-6 py-7">
            <header className="mb-4 border-b border-neutral-200 pb-4 pr-10 dark:border-neutral-800">
              <h2 id="post-modal-title" className="text-xl font-bold text-neutral-900 dark:text-neutral-100">
                {data.title}
              </h2>
              <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-neutral-600 dark:text-neutral-500">
                <span className="font-medium text-neutral-800 dark:text-neutral-300">{data.authorName}</span>
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
                {data.vulnerabilityId && (
                  <Link
                    href={`/cve/${data.vulnerabilityId}`}
                    onClick={onClose}
                    className="ml-auto inline-flex items-center gap-1 rounded-full bg-sky-100 px-2 py-0.5 text-sky-800 hover:bg-sky-200 dark:bg-sky-500/15 dark:text-sky-200 dark:hover:bg-sky-500/25"
                  >
                    <ExternalLink className="h-3 w-3" />
                    연결된 CVE
                  </Link>
                )}
              </div>
            </header>

            <div className="whitespace-pre-wrap break-words text-sm leading-relaxed text-neutral-800 dark:text-neutral-200">
              {data.content}
            </div>

            {data.canManage && (
              <div className="mt-6 flex items-center justify-end gap-2">
                {!data.isOwner && (
                  <span className="inline-flex items-center gap-1 rounded-full bg-amber-100 px-2 py-0.5 text-[11px] font-medium text-amber-800 dark:bg-amber-500/15 dark:text-amber-200">
                    관리자 권한
                  </span>
                )}
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    const msg = data.isOwner
                      ? "이 글을 삭제하시겠습니까?"
                      : "관리자 권한으로 이 글을 삭제하시겠습니까?";
                    if (confirm(msg)) remove.mutate();
                  }}
                  disabled={remove.isPending}
                  className="gap-1 border-red-300 text-red-700 hover:bg-red-50 dark:border-red-900/50 dark:text-red-300 dark:hover:bg-red-950/40"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  삭제
                </Button>
              </div>
            )}

            <CommentThread postId={data.id} />
          </article>
        )}
      </div>
    </div>
  );
}
