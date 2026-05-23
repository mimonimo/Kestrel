"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { MessageSquare, Trash2 } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { recordCommentHistory } from "@/lib/comment-history";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { formatRelativeKo } from "@/lib/format";

interface Props {
  postId?: number;
  vulnerabilityId?: string;
}

export function CommentThread({ postId, vulnerabilityId }: Props) {
  const qc = useQueryClient();
  const queryKey = ["community-comments", { postId, vulnerabilityId }];

  const list = useQuery({
    queryKey,
    queryFn: () => api.listComments({ postId, vulnerabilityId }),
    enabled: postId !== undefined || !!vulnerabilityId,
    staleTime: 5_000,
  });

  const [content, setContent] = useState("");
  const [authorName, setAuthorName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () =>
      api.createComment({
        content: content.trim(),
        authorName: authorName.trim() || undefined,
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
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!content.trim()) return;
            create.mutate();
          }}
          className="space-y-2"
        >
          <Input
            placeholder="이름 (선택)"
            value={authorName}
            onChange={(e) => setAuthorName(e.target.value)}
            maxLength={64}
          />
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
                  {c.isOwner && (
                    <button
                      type="button"
                      onClick={() => {
                        if (confirm("이 댓글을 삭제할까요?")) remove.mutate(c.id);
                      }}
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
