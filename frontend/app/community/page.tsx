"use client";

import Link from "next/link";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { MessageSquare, Plus, Eye, Hash, Sparkles } from "lucide-react";

import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { NewPostModal } from "@/components/community/NewPostModal";
import { formatRelativeKo } from "@/lib/format";

export default function CommunityPage() {
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState(false);
  const { data, isPending, isError, refetch } = useQuery({
    queryKey: ["community-posts", page],
    queryFn: () => api.listPosts(page, 20),
    staleTime: 10_000,
  });

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.pageSize)) : 1;

  return (
    <div className="mx-auto max-w-5xl px-6 py-10">
      <header className="mb-6 flex items-end justify-between border-b border-neutral-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-neutral-100">커뮤니티</h1>
          <p className="mt-1 text-sm text-neutral-500">
            CVE에 대한 분석·완화 방안·실전 사례를 공유합니다. 로그인 없이 익명으로 작성합니다.
          </p>
        </div>
        <Button onClick={() => setOpen(true)} className="gap-2">
          <Plus className="h-4 w-4" />새 글
        </Button>
      </header>

      {isPending ? (
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-20 animate-pulse rounded-lg border border-neutral-800 bg-surface-1/50" />
          ))}
        </div>
      ) : isError ? (
        <div className="rounded-lg border border-red-900/40 bg-red-950/30 p-6 text-sm text-red-300">
          글 목록을 불러오지 못했습니다.{" "}
          <button onClick={() => refetch()} className="underline">
            다시 시도
          </button>
        </div>
      ) : data && data.items.length === 0 ? (
        <div className="overflow-hidden rounded-xl border border-sky-500/30 bg-gradient-to-br from-sky-500/10 via-blue-500/5 to-transparent px-6 py-12 text-center shadow-[0_0_0_1px_rgba(56,189,248,0.05)]">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-sky-500/15 ring-1 ring-sky-400/30">
            <Sparkles className="h-6 w-6 text-sky-300" />
          </div>
          <h3 className="text-base font-semibold text-neutral-100">첫 번째 글의 주인공이 되어보세요</h3>
          <p className="mt-1 text-sm text-neutral-300">
            CVE 분석, 완화 방안, 실전 사례 — 어떤 주제든 공유해 주세요.
          </p>
          <Button onClick={() => setOpen(true)} className="mt-5 gap-2 bg-sky-500 text-white hover:bg-sky-400">
            <Plus className="h-4 w-4" />첫 글 작성하기
          </Button>
        </div>
      ) : (
        <ul className="space-y-3">
          {data?.items.map((p) => (
            <li
              key={p.id}
              className="rounded-lg border border-neutral-800 bg-surface-1 p-4 transition-colors hover:border-neutral-700"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <Link
                    href={`/community/${p.id}`}
                    className="block truncate text-base font-semibold text-neutral-100 hover:text-blue-400"
                  >
                    {p.title}
                  </Link>
                  <p className="mt-1 line-clamp-2 text-sm text-neutral-400">{p.content}</p>
                  <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-neutral-500">
                    <span>{p.authorName}</span>
                    <span>·</span>
                    <span>{formatRelativeKo(p.createdAt)}</span>
                    {p.vulnerabilityId && (
                      <>
                        <span>·</span>
                        <span className="inline-flex items-center gap-1 rounded bg-blue-500/10 px-1.5 py-0.5 text-blue-300">
                          <Hash className="h-3 w-3" />
                          CVE 연결
                        </span>
                      </>
                    )}
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-3 text-xs text-neutral-500">
                  <span className="inline-flex items-center gap-1">
                    <MessageSquare className="h-3.5 w-3.5" />
                    {p.commentCount}
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <Eye className="h-3.5 w-3.5" />
                    {p.viewCount}
                  </span>
                </div>
              </div>
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
          <span className="text-neutral-500">
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
    </div>
  );
}
