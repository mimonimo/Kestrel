"use client";

// CVE 상세에 붙는 "커뮤니티 분석" — 이 취약점에 대한 공개 분석(사람·🤖 에이전트)을
// 작성자 프로필 링크와 함께 보여줘 취약점 페이지를 커뮤니티와 연동한다.
import Link from "next/link";
import type { Route } from "next";
import { useQuery } from "@tanstack/react-query";
import { Users } from "lucide-react";

import { api } from "@/lib/api";
import { formatRelativeKo } from "@/lib/format";
import { Card, CardContent, CardHeader } from "@/components/ui/card";

export function CveCommunity({ cveId }: { cveId: string }) {
  const q = useQuery({
    queryKey: ["cve-community-analyses", cveId],
    queryFn: () => api.listCveAnalyses(cveId),
    staleTime: 60_000,
  });
  const items = (q.data?.items ?? []).filter((a) => a.visibility === "public");
  if (q.isLoading || items.length === 0) return null;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center gap-2">
        <Users className="h-4 w-4 text-neutral-500" />
        <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
          커뮤니티 분석 <span className="font-normal text-neutral-400">{items.length}</span>
        </h2>
        <Link href={"/community" as never} className="ml-auto text-[11px] text-sky-600 hover:underline dark:text-sky-400">
          커뮤니티에서 보기 →
        </Link>
      </CardHeader>
      <CardContent>
        <ul className="divide-y divide-neutral-100 dark:divide-neutral-800/60">
          {items.map((a) => {
            const href = (a.author.isAgent && a.author.id ? `/agents/${a.author.id}` : `/users/${a.author.username}`) as Route;
            return (
              <li key={a.id} className="py-2.5">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
                  <Link href={href} className="font-medium text-neutral-800 hover:underline dark:text-neutral-200">
                    {a.author.nickname || a.author.username}
                  </Link>
                  {a.author.isAgent && (
                    <span className="inline-flex items-center gap-0.5 rounded-full bg-sky-100 px-1.5 py-0.5 text-[9px] font-semibold text-sky-700 dark:bg-sky-500/15 dark:text-sky-200">
                      🤖 {a.author.persona || "AI"}
                    </span>
                  )}
                  {a.title && <span className="text-neutral-500 dark:text-neutral-400">· {a.title}</span>}
                  <span className="ml-auto tabular-nums text-[10px] text-neutral-400">{formatRelativeKo(a.createdAt)}</span>
                </div>
                {a.attackMethod && (
                  <p className="mt-1 line-clamp-2 text-[11px] leading-relaxed text-neutral-600 dark:text-neutral-400">
                    {a.attackMethod}
                  </p>
                )}
                <div className="mt-1 flex gap-2 text-[10px] text-neutral-400">
                  <span>페이로드 {a.payloadCount}</span>
                  <span>완화 {a.mitigationCount}</span>
                </div>
              </li>
            );
          })}
        </ul>
      </CardContent>
    </Card>
  );
}
