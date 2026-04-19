"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Trash2 } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
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
    onSuccess: () => {
      setContent("");
      setError(null);
      qc.invalidateQueries({ queryKey });
    },
    onError: (err) =>
      setError(err instanceof ApiError ? err.message : "댓글 작성에 실패했습니다."),
  });

  const remove = useMutation({
    mutationFn: (id: number) => api.deleteComment(id),
    onSuccess: () => qc.invalidateQueries({ queryKey }),
  });

  return (
    <section className="mt-8 border-t border-neutral-800 pt-6">
      <h3 className="mb-4 text-sm font-semibold text-neutral-200">
        댓글 <span className="text-neutral-500">({list.data?.total ?? 0})</span>
      </h3>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!content.trim()) return;
          create.mutate();
        }}
        className="mb-6 space-y-2"
      >
        <Input
          placeholder="이름 (선택)"
          value={authorName}
          onChange={(e) => setAuthorName(e.target.value)}
          maxLength={64}
        />
        <textarea
          className="block min-h-[80px] w-full rounded-md border border-neutral-800 bg-surface-2 p-3 text-sm text-neutral-100 placeholder:text-neutral-500 focus:border-neutral-600 focus:outline-none"
          placeholder="댓글을 남겨주세요…"
          value={content}
          onChange={(e) => setContent(e.target.value)}
          maxLength={4000}
        />
        {error && <p className="text-xs text-red-400">{error}</p>}
        <div className="flex justify-end">
          <Button type="submit" size="sm" disabled={create.isPending || !content.trim()}>
            {create.isPending ? "등록 중..." : "댓글 등록"}
          </Button>
        </div>
      </form>

      {list.isPending ? (
        <p className="text-xs text-neutral-500">불러오는 중…</p>
      ) : list.data && list.data.items.length === 0 ? (
        <p className="rounded border border-dashed border-neutral-800 bg-surface-1/50 py-6 text-center text-xs text-neutral-500">
          아직 댓글이 없습니다.
        </p>
      ) : (
        <ul className="space-y-3">
          {list.data?.items.map((c) => (
            <li
              key={c.id}
              className="rounded-lg border border-neutral-800 bg-surface-1 p-3 text-sm text-neutral-200"
            >
              <div className="mb-1 flex items-center justify-between text-xs text-neutral-500">
                <div>
                  <span className="font-medium text-neutral-300">{c.authorName}</span>
                  <span className="mx-1.5">·</span>
                  <span>{formatRelativeKo(c.createdAt)}</span>
                </div>
                {c.isOwner && (
                  <button
                    type="button"
                    onClick={() => {
                      if (confirm("댓글을 삭제하시겠습니까?")) remove.mutate(c.id);
                    }}
                    className="inline-flex items-center gap-1 text-neutral-500 hover:text-red-400"
                    aria-label="댓글 삭제"
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                )}
              </div>
              <p className="whitespace-pre-wrap break-words">{c.content}</p>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
