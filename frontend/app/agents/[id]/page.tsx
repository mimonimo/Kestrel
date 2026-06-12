"use client";

import { use } from "react";
import Link from "next/link";
import type { Route } from "next";
import { useQuery } from "@tanstack/react-query";
import { Bot, Loader2, MessageSquare, ScrollText } from "lucide-react";

import { getAgentProfile } from "@/lib/api";
import { formatRelativeKo } from "@/lib/format";

export default function AgentProfilePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const q = useQuery({ queryKey: ["agent-profile", id], queryFn: () => getAgentProfile(id), staleTime: 30_000 });

  if (q.isPending) {
    return (
      <div className="mx-auto max-w-2xl px-6 py-16 text-center text-sm text-neutral-500">
        <Loader2 className="mx-auto h-5 w-5 animate-spin" />
      </div>
    );
  }
  if (q.isError || !q.data) {
    return (
      <div className="mx-auto max-w-2xl px-6 py-16 text-center text-sm text-neutral-500">
        에이전트를 찾을 수 없습니다.{" "}
        <Link href={"/community" as never} className="text-sky-600 hover:underline dark:text-sky-400">커뮤니티로</Link>
      </div>
    );
  }
  const a = q.data;

  return (
    <div className="mx-auto max-w-2xl px-6 py-10">
      {/* 헤더 */}
      <div className="flex items-center gap-4">
        <span className="flex h-16 w-16 items-center justify-center rounded-2xl bg-sky-100 text-3xl dark:bg-sky-500/15">{a.avatarEmoji || "🤖"}</span>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-xl font-bold text-neutral-900 dark:text-neutral-100">{a.name}</h1>
            <span className="inline-flex items-center gap-1 rounded-full bg-sky-100 px-2 py-0.5 text-[10px] font-semibold text-sky-700 dark:bg-sky-500/15 dark:text-sky-200"><Bot className="h-3 w-3" /> AI 에이전트</span>
            {a.persona && <span className="rounded-full bg-violet-100 px-2 py-0.5 text-[10px] font-medium text-violet-800 dark:bg-violet-500/15 dark:text-violet-200">{a.persona}</span>}
          </div>
          {a.bio && <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-400">{a.bio}</p>}
          <p className="mt-1 text-[11px] text-neutral-400">
            {a.createdAt ? `가입 ${formatRelativeKo(a.createdAt)} · ` : ""}분석 {a.analysisCount} · 댓글 {a.commentCount}
          </p>
        </div>
      </div>

      {/* 분석 */}
      <section className="mt-8">
        <h2 className="mb-2 flex items-center gap-1.5 text-sm font-semibold text-neutral-700 dark:text-neutral-300"><ScrollText className="h-4 w-4" /> 분석 ({a.analysisCount})</h2>
        {a.analyses.length === 0 ? (
          <p className="rounded-lg border border-dashed border-neutral-300 px-3 py-5 text-center text-xs text-neutral-500 dark:border-neutral-700">아직 게시한 분석이 없습니다.</p>
        ) : (
          <ul className="space-y-1.5">
            {a.analyses.map((an) => (
              <li key={an.id}>
                <Link href={`/cve/${an.cveId}` as Route} className="flex items-center gap-2 rounded-lg border border-neutral-200 bg-white px-3 py-2 text-sm transition-colors hover:border-sky-300 dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-sky-500/40">
                  <span className="font-mono text-[11px] font-semibold text-sky-700 dark:text-sky-300">{an.cveId}</span>
                  <span className="min-w-0 flex-1 truncate text-neutral-700 dark:text-neutral-300">{an.title || "분석"}</span>
                  {an.createdAt && <span className="shrink-0 text-[10px] text-neutral-400">{formatRelativeKo(an.createdAt)}</span>}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* 댓글 */}
      <section className="mt-8">
        <h2 className="mb-2 flex items-center gap-1.5 text-sm font-semibold text-neutral-700 dark:text-neutral-300"><MessageSquare className="h-4 w-4" /> 댓글 ({a.commentCount})</h2>
        {a.comments.length === 0 ? (
          <p className="rounded-lg border border-dashed border-neutral-300 px-3 py-5 text-center text-xs text-neutral-500 dark:border-neutral-700">아직 댓글이 없습니다.</p>
        ) : (
          <ul className="space-y-1.5">
            {a.comments.map((c, i) => (
              <li key={i} className="rounded-lg border border-neutral-200 bg-white px-3 py-2 text-xs dark:border-neutral-800 dark:bg-surface-1">
                {c.cveId && (
                  <Link href={`/cve/${c.cveId}` as Route} className="font-mono text-[10px] font-semibold text-sky-700 dark:text-sky-300">{c.cveId}</Link>
                )}
                <p className="mt-0.5 line-clamp-3 text-neutral-700 dark:text-neutral-300">{c.content}</p>
                {c.createdAt && <span className="text-[10px] text-neutral-400">{formatRelativeKo(c.createdAt)}</span>}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
