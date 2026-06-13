"use client";

import { use } from "react";
import Link from "next/link";
import type { Route } from "next";
import { useQuery } from "@tanstack/react-query";
import { Bot, Loader2, ScrollText, ShieldCheck } from "lucide-react";

import { getUserProfile } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { MyAnalysesManager } from "@/components/community/MyAnalysesManager";
import { AgentsManagePanel } from "@/components/settings/AgentsManagePanel";
import { formatRelativeKo } from "@/lib/format";

export default function UserProfilePage({ params }: { params: Promise<{ username: string }> }) {
  const { username } = use(params);
  const { user } = useAuth();
  const q = useQuery({ queryKey: ["user-profile", username], queryFn: () => getUserProfile(username), staleTime: 30_000 });

  if (q.isPending) {
    return <div className="mx-auto max-w-2xl px-6 py-16 text-center"><Loader2 className="mx-auto h-5 w-5 animate-spin text-neutral-400" /></div>;
  }
  if (q.isError || !q.data) {
    return (
      <div className="mx-auto max-w-2xl px-6 py-16 text-center text-sm text-neutral-500">
        사용자를 찾을 수 없습니다. <Link href={"/community" as never} className="text-sky-600 hover:underline dark:text-sky-400">커뮤니티로</Link>
      </div>
    );
  }
  const u = q.data;
  const display = u.nickname || u.username;
  const initial = display.trim().charAt(0).toUpperCase() || "?";
  const isMe = !!user && user.username === u.username;

  return (
    <div className="mx-auto max-w-2xl px-6 py-10">
      {/* 헤더 */}
      <div className="flex items-center gap-4">
        <span className="flex h-16 w-16 items-center justify-center rounded-full bg-sky-100 text-2xl font-bold text-sky-700 dark:bg-sky-500/15 dark:text-sky-300">{initial}</span>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-xl font-bold text-neutral-900 dark:text-neutral-100">{display}</h1>
            {u.isAdmin && <span className="inline-flex items-center gap-1 rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-medium text-amber-800 dark:bg-amber-500/15 dark:text-amber-200"><ShieldCheck className="h-3 w-3" /> 관리자</span>}
          </div>
          <p className="text-xs text-neutral-500 dark:text-neutral-500">@{u.username}</p>
          {u.bio && <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-400">{u.bio}</p>}
          <p className="mt-1 text-[11px] text-neutral-400">
            {u.createdAt ? `가입 ${formatRelativeKo(u.createdAt)} · ` : ""}공유 분석 {u.analysisCount} · 에이전트 {u.agentCount}
          </p>
        </div>
      </div>

      {/* 보유 에이전트 — 내 프로필이면 관리(등록·수정·토큰·삭제), 타인은 목록만 */}
      {isMe ? (
        <section className="mt-8">
          <h2 className="mb-2 flex items-center gap-1.5 text-sm font-semibold text-neutral-700 dark:text-neutral-300">
            <Bot className="h-4 w-4" /> 에이전트 관리 ({u.agentCount})
          </h2>
          <AgentsManagePanel />
        </section>
      ) : (
        u.agents.length > 0 && (
        <section className="mt-8">
          <h2 className="mb-2 flex items-center gap-1.5 text-sm font-semibold text-neutral-700 dark:text-neutral-300"><Bot className="h-4 w-4" /> 에이전트 ({u.agentCount})</h2>
          <ul className="grid gap-2 sm:grid-cols-2">
            {u.agents.map((ag) => (
              <li key={ag.id}>
                <Link href={`/agents/${ag.id}` as Route} className="flex items-center gap-2 rounded-lg border border-neutral-200 bg-white px-3 py-2 transition-colors hover:border-sky-300 dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-sky-500/40">
                  <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-sky-100 text-base dark:bg-sky-500/15">{ag.avatarEmoji || "🤖"}</span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">{ag.name}</span>
                    <span className="block text-[10px] text-neutral-500">{ag.persona || "에이전트"} · 분석 {ag.analyses}</span>
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </section>
        )
      )}

      {/* 공유 분석 — 내 프로필이면 관리(공개/비공개·삭제), 타인 프로필이면 공개 목록만 */}
      {isMe ? (
        <MyAnalysesManager />
      ) : (
        <section className="mt-8">
          <h2 className="mb-2 flex items-center gap-1.5 text-sm font-semibold text-neutral-700 dark:text-neutral-300"><ScrollText className="h-4 w-4" /> 공유한 분석 ({u.analysisCount})</h2>
          {u.analyses.length === 0 ? (
            <p className="rounded-lg border border-dashed border-neutral-300 px-3 py-5 text-center text-xs text-neutral-500 dark:border-neutral-700">공개한 분석이 없습니다.</p>
          ) : (
            <ul className="space-y-1.5">
              {u.analyses.map((an) => (
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
      )}
    </div>
  );
}
