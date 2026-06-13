"use client";

// 커뮤니티 "공지" 탭 — 누구나 조회, 관리자만 작성/삭제.
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Megaphone, Pin, Plus, Trash2 } from "lucide-react";

import { api, type CommunityNotice } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { Button } from "@/components/ui/button";
import { ErrorBox } from "@/components/ui/feedback-box";
import { MarkdownLite } from "@/components/ui/markdown-lite";
import { formatRelativeKo } from "@/lib/format";
import { cn } from "@/lib/utils";

export function CommunityNotices() {
  const qc = useQueryClient();
  const { user } = useAuth();
  const isAdmin = !!user?.isAdmin;
  const [composing, setComposing] = useState(false);
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [pinned, setPinned] = useState(false);

  const list = useQuery({
    queryKey: ["community-notices"],
    queryFn: () => api.listNotices(),
    staleTime: 30_000,
  });

  const create = useMutation({
    mutationFn: () => api.createNotice({ title: title.trim(), content: content.trim(), pinned }),
    onSuccess: () => {
      setTitle("");
      setContent("");
      setPinned(false);
      setComposing(false);
      qc.invalidateQueries({ queryKey: ["community-notices"] });
    },
  });
  const remove = useMutation({
    mutationFn: (id: number) => api.deleteNotice(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["community-notices"] }),
  });

  const notices = list.data ?? [];

  return (
    <div>
      {isAdmin && (
        <div className="mb-4">
          {composing ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (!title.trim() || !content.trim()) return;
                create.mutate();
              }}
              className="space-y-2 rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-surface-1"
            >
              <input
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="공지 제목"
                maxLength={255}
                className="block w-full rounded-lg border border-neutral-300 bg-white px-3 py-2 text-sm font-medium text-neutral-900 focus:border-sky-500 focus:outline-none dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100"
              />
              <textarea
                value={content}
                onChange={(e) => setContent(e.target.value)}
                placeholder="내용 (마크다운 지원)"
                rows={5}
                maxLength={20000}
                className="block w-full rounded-lg border border-neutral-300 bg-white px-3 py-2 text-sm text-neutral-900 focus:border-sky-500 focus:outline-none dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-100"
              />
              <div className="flex items-center justify-between gap-2">
                <label className="inline-flex items-center gap-1.5 text-xs text-neutral-600 dark:text-neutral-400">
                  <input type="checkbox" checked={pinned} onChange={(e) => setPinned(e.target.checked)} className="rounded" />
                  <Pin className="h-3 w-3" /> 상단 고정
                </label>
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => setComposing(false)}
                    className="rounded-full px-3 py-1.5 text-xs text-neutral-600 hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-surface-2"
                  >
                    취소
                  </button>
                  <Button
                    type="submit"
                    size="sm"
                    disabled={create.isPending || !title.trim() || !content.trim()}
                    className="gap-1 rounded-full bg-sky-500 text-white hover:bg-sky-600 disabled:opacity-50"
                  >
                    {create.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Megaphone className="h-3.5 w-3.5" />}
                    공지 등록
                  </Button>
                </div>
              </div>
            </form>
          ) : (
            <Button onClick={() => setComposing(true)} size="sm" className="gap-1.5">
              <Plus className="h-4 w-4" /> 공지 작성
            </Button>
          )}
        </div>
      )}

      {list.isPending ? (
        <div className="flex items-center gap-2 py-8 text-sm text-neutral-500">
          <Loader2 className="h-4 w-4 animate-spin" /> 불러오는 중…
        </div>
      ) : list.isError ? (
        <ErrorBox title="공지를 불러오지 못했습니다" message="잠시 후 다시 시도해 주세요." />
      ) : notices.length === 0 ? (
        <div className="rounded-xl border border-dashed border-neutral-300 bg-white px-6 py-12 text-center dark:border-neutral-700 dark:bg-surface-1">
          <Megaphone className="mx-auto mb-2 h-6 w-6 text-neutral-400" />
          <p className="text-sm text-neutral-600 dark:text-neutral-400">등록된 공지가 없습니다.</p>
        </div>
      ) : (
        <ul className="space-y-3">
          {notices.map((n: CommunityNotice) => (
            <li
              key={n.id}
              className={cn(
                "rounded-2xl border bg-white p-4 dark:bg-surface-1 sm:p-5",
                n.pinned
                  ? "border-amber-300 ring-1 ring-amber-200/60 dark:border-amber-500/40 dark:ring-amber-500/20"
                  : "border-neutral-200 dark:border-neutral-800",
              )}
            >
              <div className="mb-1 flex items-start justify-between gap-2">
                <h3 className="flex items-center gap-1.5 text-base font-semibold text-neutral-900 dark:text-neutral-100">
                  {n.pinned && <Pin className="h-3.5 w-3.5 shrink-0 text-amber-500" />}
                  {n.title}
                </h3>
                {n.canManage && (
                  <button
                    type="button"
                    onClick={() => {
                      if (confirm("이 공지를 삭제할까요?")) remove.mutate(n.id);
                    }}
                    title="공지 삭제"
                    className="shrink-0 rounded-full p-1 text-neutral-400 hover:bg-rose-50 hover:text-rose-600 dark:hover:bg-rose-950/40 dark:hover:text-rose-300"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
              <div className="mb-2 text-[11px] text-neutral-500 dark:text-neutral-500">
                {n.authorName} · {formatRelativeKo(n.createdAt)}
              </div>
              <div className="text-sm">
                <MarkdownLite source={n.content} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
