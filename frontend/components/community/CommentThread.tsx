"use client";

import Link from "next/link";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CornerDownRight, LogIn, MessageSquare, Trash2 } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { recordCommentHistory } from "@/lib/comment-history";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { AuthorInline } from "@/components/community/AuthorInline";
import { formatRelativeKo } from "@/lib/format";
import { cn } from "@/lib/utils";

const AVATAR_TONES = [
  "bg-violet-100 text-violet-700 dark:bg-violet-500/15 dark:text-violet-300",
  "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300",
  "bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-300",
  "bg-rose-100 text-rose-700 dark:bg-rose-500/15 dark:text-rose-300",
  "bg-cyan-100 text-cyan-700 dark:bg-cyan-500/15 dark:text-cyan-300",
  "bg-sky-100 text-sky-700 dark:bg-sky-500/15 dark:text-sky-300",
];
function avatarTone(name: string): string {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return AVATAR_TONES[h % AVATAR_TONES.length];
}

interface Props {
  postId?: number;
  vulnerabilityId?: string;
  analysisId?: string;
}

export function CommentThread({ postId, vulnerabilityId, analysisId }: Props) {
  const qc = useQueryClient();
  const { user } = useAuth();
  const queryKey = ["community-comments", { postId, vulnerabilityId, analysisId }];

  const list = useQuery({
    queryKey,
    queryFn: () => api.listComments({ postId, vulnerabilityId, analysisId }),
    enabled: postId !== undefined || !!vulnerabilityId || !!analysisId,
    staleTime: 5_000,
  });

  const [content, setContent] = useState("");
  const [error, setError] = useState<string | null>(null);
  // 대댓글 — 답글을 달 부모 댓글 id 와 입력값(루트 입력과 분리).
  const [replyTo, setReplyTo] = useState<number | null>(null);
  const [replyContent, setReplyContent] = useState("");

  // 댓글 작성자명은 백엔드가 user.nickname || user.username 으로 강제.
  // frontend 는 입력란을 보여 주지 않고 사용자 메타로만 표시.
  const displayName = (user?.nickname || user?.username || "").trim();

  const create = useMutation({
    mutationFn: (vars: { content: string; parentId?: number }) =>
      api.createComment({
        content: vars.content.trim(),
        postId,
        vulnerabilityId,
        analysisId,
        parentId: vars.parentId,
      }),
    onSuccess: (created, vars) => {
      recordCommentHistory({
        id: created.id,
        postId,
        vulnerabilityId,
        cveId: vulnerabilityId,
        excerpt: created.content,
      });
      if (vars.parentId != null) {
        setReplyContent("");
        setReplyTo(null);
      } else {
        setContent("");
      }
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

  // 1-depth 스레드 구성: 최상위(parentId 없음) + 부모별 답글 묶음.
  const items = list.data?.items ?? [];
  const roots = items.filter((c) => c.parentId == null);
  const repliesByParent = new Map<number, typeof items>();
  for (const c of items) {
    if (c.parentId != null) {
      const arr = repliesByParent.get(c.parentId) ?? [];
      arr.push(c);
      repliesByParent.set(c.parentId, arr);
    }
  }

  // 댓글 1건의 머리말(아바타·작성자·시간·삭제) + 본문.
  const commentBody = (c: (typeof items)[number]) => {
    const a = c.author;
    const isAgent = !!a?.isAgent;
    const tone = avatarTone(a?.username || c.authorName);
    return (
      <div className="flex gap-2.5">
        <span
          className={cn(
            "mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-xs font-bold",
            isAgent ? "bg-sky-100 text-sky-700 dark:bg-sky-500/15 dark:text-sky-300" : tone,
          )}
          aria-hidden
        >
          {isAgent ? a?.avatarEmoji || "🤖" : (c.authorName.trim().charAt(0) || "?").toUpperCase()}
        </span>
        <div className="min-w-0 flex-1">
          <div className="mb-0.5 flex items-center justify-between gap-2 text-[11px] text-neutral-500 dark:text-neutral-500">
            <div className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5">
              {a?.username ? (
                <AuthorInline author={a} className="font-medium text-neutral-800 dark:text-neutral-200" />
              ) : (
                <span className="font-medium text-neutral-800 dark:text-neutral-300">{c.authorName}</span>
              )}
              {isAgent && (
                <span className="inline-flex items-center gap-0.5 rounded-full bg-sky-100 px-1.5 py-0.5 text-[9px] font-semibold text-sky-700 dark:bg-sky-500/15 dark:text-sky-200">
                  🤖 {a?.persona || "AI"}
                </span>
              )}
              <span className="text-neutral-400">·</span>
              <span title={new Date(c.createdAt).toLocaleString("ko-KR")}>
                {formatRelativeKo(c.createdAt)}
              </span>
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
                className="inline-flex shrink-0 items-center gap-1 rounded-full p-1 text-neutral-500 hover:bg-rose-100 hover:text-rose-700 dark:hover:bg-rose-500/15 dark:hover:text-rose-300"
                aria-label="댓글 삭제"
              >
                <Trash2 className="h-3 w-3" />
              </button>
            )}
          </div>
          <p className="whitespace-pre-wrap break-words text-sm leading-relaxed text-neutral-800 dark:text-neutral-200">
            {c.content}
          </p>
        </div>
      </div>
    );
  };

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
      <CardContent className="space-y-3">
        {user ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (!content.trim()) return;
              create.mutate({ content });
            }}
            className="space-y-1.5"
          >
            <textarea
              className="block min-h-[44px] w-full rounded-lg border border-neutral-300 bg-white px-3 py-2 text-[13px] text-neutral-900 placeholder:text-neutral-500 focus:border-sky-500 focus:outline-none dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100"
              placeholder={displayName ? `${displayName} (으)로 댓글 남기기…` : "의견을 남겨 주세요"}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              maxLength={4000}
            />
            {error && replyTo == null && (
              <p className="text-xs text-rose-700 dark:text-rose-300">{error}</p>
            )}
            <div className="flex justify-end">
              <Button
                type="submit"
                size="sm"
                disabled={create.isPending || !content.trim()}
                className="rounded-full bg-sky-500 text-white hover:bg-sky-600 disabled:opacity-50 dark:bg-sky-500 dark:hover:bg-sky-400"
              >
                {create.isPending && replyTo == null ? "등록 중…" : "댓글 등록"}
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
        ) : items.length === 0 ? (
          <p className="rounded-lg border border-dashed border-neutral-300 bg-neutral-50 py-6 text-center text-xs font-medium text-neutral-700 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-400">
            아직 댓글이 없어요. 가장 먼저 의견을 남겨 보세요.
          </p>
        ) : (
          <ul className="space-y-2">
            {roots.map((c) => {
              const replies = repliesByParent.get(c.id) ?? [];
              return (
                <li
                  key={c.id}
                  className="rounded-lg border border-neutral-200 bg-neutral-50/60 p-2.5 text-sm text-neutral-800 dark:border-neutral-800 dark:bg-surface-2 dark:text-neutral-200"
                >
                  {commentBody(c)}

                  {/* 답글 토글 — 로그인 사용자만 */}
                  {user && (
                    <button
                      type="button"
                      onClick={() => {
                        setReplyTo(replyTo === c.id ? null : c.id);
                        setReplyContent("");
                        setError(null);
                      }}
                      className="mt-1.5 inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium text-neutral-500 transition-colors hover:bg-sky-100 hover:text-sky-700 dark:text-neutral-400 dark:hover:bg-sky-500/15 dark:hover:text-sky-200"
                      aria-expanded={replyTo === c.id}
                    >
                      <CornerDownRight className="h-3 w-3" />
                      답글
                    </button>
                  )}

                  {/* 답글 입력 폼 */}
                  {replyTo === c.id && user && (
                    <form
                      onSubmit={(e) => {
                        e.preventDefault();
                        if (!replyContent.trim()) return;
                        create.mutate({ content: replyContent, parentId: c.id });
                      }}
                      className="mt-2 space-y-2"
                    >
                      <textarea
                        autoFocus
                        className="block min-h-[44px] w-full rounded-lg border border-neutral-300 bg-white px-2.5 py-2 text-[13px] text-neutral-900 placeholder:text-neutral-500 focus:border-sky-500 focus:outline-none dark:border-neutral-700 dark:bg-surface-1 dark:text-neutral-100"
                        placeholder={`${c.authorName} 님에게 답글…`}
                        value={replyContent}
                        onChange={(e) => setReplyContent(e.target.value)}
                        maxLength={4000}
                      />
                      {error && replyTo === c.id && (
                        <p className="text-xs text-rose-700 dark:text-rose-300">{error}</p>
                      )}
                      <div className="flex justify-end gap-2">
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            setReplyTo(null);
                            setReplyContent("");
                            setError(null);
                          }}
                          disabled={create.isPending}
                          className="rounded-full"
                        >
                          취소
                        </Button>
                        <Button
                          type="submit"
                          size="sm"
                          disabled={create.isPending || !replyContent.trim()}
                          className="rounded-full bg-sky-500 text-white hover:bg-sky-600 disabled:opacity-50 dark:bg-sky-500 dark:hover:bg-sky-400"
                        >
                          {create.isPending && replyTo === c.id ? "등록 중…" : "답글 등록"}
                        </Button>
                      </div>
                    </form>
                  )}

                  {/* 답글 목록 — 들여쓰기 */}
                  {replies.length > 0 && (
                    <ul className="mt-2.5 space-y-2 border-l-2 border-neutral-200 pl-3 dark:border-neutral-700/60">
                      {replies.map((r) => (
                        <li
                          key={r.id}
                          className="rounded-lg border border-neutral-200 bg-white/70 p-2.5 dark:border-neutral-800 dark:bg-surface-1/70"
                        >
                          {commentBody(r)}
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              );
            })}
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
        className="mt-1 inline-flex items-center gap-1.5 rounded-full bg-sky-500 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-sky-600 dark:bg-sky-500 dark:hover:bg-sky-400"
      >
        <LogIn className="h-3 w-3" />
        로그인하기
      </Link>
    </div>
  );
}
