"use client";

import Link from "next/link";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LogIn, MessageSquare, Trash2 } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { recordCommentHistory } from "@/lib/comment-history";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { formatRelativeKo } from "@/lib/format";

interface Props {
  postId?: number;
  vulnerabilityId?: string;
}

export function CommentThread({ postId, vulnerabilityId }: Props) {
  const qc = useQueryClient();
  const { user } = useAuth();
  const queryKey = ["community-comments", { postId, vulnerabilityId }];

  const list = useQuery({
    queryKey,
    queryFn: () => api.listComments({ postId, vulnerabilityId }),
    enabled: postId !== undefined || !!vulnerabilityId,
    staleTime: 5_000,
  });

  const [content, setContent] = useState("");
  const [error, setError] = useState<string | null>(null);

  // 댓글 작성자명은 백엔드가 user.nickname || user.username 으로 강제.
  // frontend 는 입력란을 보여 주지 않고 사용자 메타로만 표시.
  const displayName = (user?.nickname || user?.username || "").trim();

  const create = useMutation({
    mutationFn: () =>
      api.createComment({
        content: content.trim(),
        postId,
        vulnerabilityId,
      }),
    onSuccess: (created) => {
      recordCommentHistory({
        id: created.id,
        postId,
        vulnerabilityId,
        cveId: vulnerabilityId,
        excerpt: created.content,
      });
      setContent("");
      setError(null);
      qc.invalidateQueries({ queryKey });
    },
    onError: (err) =>
      setError(err instanceof ApiError ? err.message : "댓글 작성에 실패했어요."),
  });

  const remove = useMutation({
    mutationFn: (id: number) => api.deleteComment(id),
    onSuccess: () => qc.invalidateQueries({ queryKey }),
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-center gap-2">
        <MessageSquare className="h-4 w-4 text-sky-600 dark:text-sky-400" />
        <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-600 dark:text-neutral-500">
          댓글
          <span className="ml-1.5 text-neutral-500 dark:text-neutral-500">
            ({list.data?.total ?? 0})
          </span>
        </h2>
      </CardHeader>
      <CardContent className="space-y-5">
        {user ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (!content.trim()) return;
              create.mutate();
            }}
            className="space-y-2"
          >
            <div className="flex items-center gap-2 rounded-md border border-neutral-200 bg-neutral-50 px-3 py-1.5 text-xs text-neutral-700 dark:border-neutral-800 dark:bg-surface-2 dark:text-neutral-300">
              <span className="text-neutral-500 dark:text-neutral-500">작성자</span>
              <span className="font-medium text-neutral-900 dark:text-neutral-100">{displayName}</span>
            </div>
            <textarea
              className="block min-h-[80px] w-full rounded-lg border border-neutral-300 bg-white p-3 text-sm text-neutral-900 placeholder:text-neutral-500 focus:border-sky-500 focus:outline-none dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100"
              placeholder="의견을 남겨 주세요"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              maxLength={4000}
            />
            {error && (
              <p className="text-xs text-rose-700 dark:text-rose-300">{error}</p>
            )}
            <div className="flex justify-end">
              <Button
                type="submit"
                size="sm"
                disabled={create.isPending || !content.trim()}
                className="rounded-full bg-sky-600 text-white hover:bg-sky-700 disabled:opacity-50 dark:bg-sky-500 dark:hover:bg-sky-400"
              >
                {create.isPending ? "등록 중…" : "댓글 등록"}
              </Button>
            </div>
          </form>
        ) : (
          <LoginGate
            label="댓글 작성"
            description="다른 사용자의 댓글은 자유롭게 읽을 수 있어요."
          />
        )}

        {list.isPending ? (
          <p className="text-xs text-neutral-600 dark:text-neutral-500">
            불러오는 중…
          </p>
        ) : list.data && list.data.items.length === 0 ? (
          <p className="rounded-lg border border-dashed border-neutral-300 bg-neutral-50 py-6 text-center text-xs font-medium text-neutral-700 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-400">
            아직 댓글이 없어요. 가장 먼저 의견을 남겨 보세요.
          </p>
        ) : (
          <ul className="space-y-2.5">
            {list.data?.items.map((c) => (
              <li
                key={c.id}
                className="rounded-lg border border-neutral-200 bg-neutral-50/60 p-3 text-sm text-neutral-800 dark:border-neutral-800 dark:bg-surface-2 dark:text-neutral-200"
              >
                <div className="mb-1 flex items-center justify-between text-[11px] text-neutral-500 dark:text-neutral-500">
                  <div>
                    <span className="font-medium text-neutral-800 dark:text-neutral-300">
                      {c.authorName}
                    </span>
                    <span className="mx-1.5">·</span>
                    <span>{formatRelativeKo(c.createdAt)}</span>
                  </div>
                  {c.canManage && (
                    <button
                      type="button"
                      onClick={() => {
                        const msg = c.isOwner
                          ? "이 댓글을 삭제할까요?"
                          : "관리자 권한으로 이 댓글을 삭제할까요?";
                        if (confirm(msg)) remove.mutate(c.id);
                      }}
                      title={c.isOwner ? "댓글 삭제" : "관리자 권한으로 삭제"}
                      className="inline-flex items-center gap-1 rounded-full p-1 text-neutral-500 hover:bg-rose-100 hover:text-rose-700 dark:hover:bg-rose-500/15 dark:hover:text-rose-300"
                      aria-label="댓글 삭제"
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                  )}
                </div>
                <p className="whitespace-pre-wrap break-words leading-relaxed">
                  {c.content}
                </p>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

function LoginGate({ label, description }: { label: string; description: string }) {
  const next =
    typeof window !== "undefined"
      ? `?next=${encodeURIComponent(window.location.pathname + window.location.search)}`
      : "";
  return (
    <div className="flex flex-col items-start gap-2 rounded-lg border border-dashed border-neutral-300 bg-neutral-50 p-4 dark:border-neutral-700 dark:bg-surface-2">
      <p className="text-sm text-neutral-800 dark:text-neutral-200">
        <span className="font-medium">{label}</span> 은 로그인 후 이용할 수 있어요.
      </p>
      <p className="text-xs text-neutral-600 dark:text-neutral-400">{description}</p>
      <Link
        href={`/login${next}` as never}
        className="mt-1 inline-flex items-center gap-1.5 rounded-full bg-sky-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-sky-500 dark:bg-sky-500 dark:hover:bg-sky-400"
      >
        <LogIn className="h-3 w-3" />
        로그인하기
      </Link>
    </div>
  );
}
