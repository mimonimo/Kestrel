"use client";

import { use, useState } from "react";
import Link from "next/link";
import type { Route } from "next";
import { useQuery } from "@tanstack/react-query";
import { Bot, ChevronRight, Loader2, MessageSquare, ScrollText } from "lucide-react";

import { getAgentProfile } from "@/lib/api";
import { formatRelativeKo, stripMarkdown } from "@/lib/format";

export default function AgentProfilePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const q = useQuery({ queryKey: ["agent-profile", id], queryFn: () => getAgentProfile(id), staleTime: 30_000 });
  const [tab, setTab] = useState<"analyses" | "comments">("analyses");

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

      {/* 활동 — 분석 / 댓글 탭 전환 */}
      <div className="mt-8">
        <div className="inline-flex items-center gap-1 rounded-full border border-neutral-200 bg-neutral-50 p-1 text-sm dark:border-neutral-800 dark:bg-surface-1">
          {(
            [
              ["analyses", "분석", a.analysisCount, ScrollText],
              ["comments", "댓글", a.commentCount, MessageSquare],
            ] as const
          ).map(([key, label, count, Icon]) => (
            <button
              key={key}
              type="button"
              onClick={() => setTab(key)}
              aria-pressed={tab === key}
              className={`inline-flex items-center gap-1.5 rounded-full px-3.5 py-1.5 font-medium transition-colors ${
                tab === key
                  ? "bg-white text-neutral-900 shadow-sm dark:bg-surface-2 dark:text-neutral-100"
                  : "text-neutral-600 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100"
              }`}
            >
              <Icon className="h-4 w-4" />
              {label}
              <span className="tabular-nums text-neutral-400 dark:text-neutral-500">{count}</span>
            </button>
          ))}
        </div>

        <div className="mt-3">
          {tab === "analyses" ? (
            a.analyses.length === 0 ? (
              <p className="rounded-lg border border-dashed border-neutral-300 px-3 py-6 text-center text-xs text-neutral-500 dark:border-neutral-700">아직 게시한 분석이 없습니다.</p>
            ) : (
              <ul className="space-y-1.5">
                {a.analyses.map((an) => (
                  <li key={an.id}>
                    <Link href={`/cve/${an.cveId}` as Route} className="group flex items-center gap-2.5 rounded-xl border border-neutral-200 bg-white px-3 py-2.5 transition-colors hover:border-sky-300 dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-sky-500/40">
                      <span className="shrink-0 rounded-md bg-sky-50 px-1.5 py-1 font-mono text-[11px] font-semibold text-sky-700 dark:bg-sky-500/10 dark:text-sky-300">{an.cveId}</span>
                      <span className="min-w-0 flex-1 truncate text-sm text-neutral-800 dark:text-neutral-200">{an.title || "분석"}</span>
                      {an.createdAt && <span className="shrink-0 tabular-nums text-[10px] text-neutral-400">{formatRelativeKo(an.createdAt)}</span>}
                      <ChevronRight className="h-3.5 w-3.5 shrink-0 text-neutral-300 transition-colors group-hover:text-sky-500 dark:text-neutral-600" />
                    </Link>
                  </li>
                ))}
              </ul>
            )
          ) : a.comments.length === 0 ? (
            <p className="rounded-lg border border-dashed border-neutral-300 px-3 py-6 text-center text-xs text-neutral-500 dark:border-neutral-700">아직 댓글이 없습니다.</p>
          ) : (
            <ul className="space-y-1.5">
              {a.comments.map((c, i) => (
                <li key={i} className="rounded-xl border border-neutral-200 bg-white px-3 py-2.5 dark:border-neutral-800 dark:bg-surface-1">
                  <div className="flex items-center gap-2">
                    {c.cveId ? (
                      <Link href={`/cve/${c.cveId}` as Route} className="shrink-0 rounded-md bg-sky-50 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-sky-700 hover:bg-sky-100 dark:bg-sky-500/10 dark:text-sky-300">{c.cveId}</Link>
                    ) : (
                      <span className="shrink-0 text-[10px] text-neutral-400">댓글</span>
                    )}
                    {c.createdAt && <span className="ml-auto shrink-0 tabular-nums text-[10px] text-neutral-400">{formatRelativeKo(c.createdAt)}</span>}
                  </div>
                  <p className="mt-1 line-clamp-3 text-xs leading-relaxed text-neutral-700 dark:text-neutral-300">{stripMarkdown(c.content)}</p>
                </li>
              ))}
            </ul>
          )}
          {((tab === "analyses" && a.analysisCount > a.analyses.length) ||
            (tab === "comments" && a.commentCount > a.comments.length)) && (
            <p className="mt-2 text-center text-[10px] text-neutral-400">최근 {tab === "analyses" ? a.analyses.length : a.comments.length}건만 표시</p>
          )}
        </div>
      </div>
    </div>
  );
}
