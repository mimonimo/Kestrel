"use client";

// 같은 제품/약점을 공유하는 연관 CVE — 분석 맥락 제공. 내부 데이터 기반.
import Link from "next/link";
import type { Route } from "next";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Flame, GitFork, Info, List, Share2 } from "lucide-react";

import { api } from "@/lib/api";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { RelatedCvesGraph } from "./RelatedCvesGraph";
import { SeverityBadge } from "./SeverityBadge";

export function RelatedCves({ cveId }: { cveId: string }) {
  const q = useQuery({
    queryKey: ["cve-related", cveId],
    queryFn: () => api.getRelatedCves(cveId),
    staleTime: 5 * 60_000,
  });
  const items = q.data ?? [];
  const [view, setView] = useState<"graph" | "list">("graph");
  if (q.isLoading || items.length === 0) return null;

  return (
    <Card>
      <CardHeader className="space-y-1.5">
        <div className="flex items-center gap-2">
          <GitFork className="h-4 w-4 text-neutral-500" />
          <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
            연관 취약점 <span className="font-normal text-neutral-400">{items.length}</span>
          </h2>
          <div className="ml-auto flex items-center gap-2">
            <div className="inline-flex overflow-hidden rounded-full border border-neutral-300 text-[11px] dark:border-neutral-700">
              <button
                type="button"
                onClick={() => setView("graph")}
                aria-pressed={view === "graph"}
                className={
                  "inline-flex items-center gap-1 px-2 py-1 transition-colors " +
                  (view === "graph"
                    ? "bg-sky-100 font-medium text-sky-800 dark:bg-sky-500/20 dark:text-sky-200"
                    : "text-neutral-600 hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-surface-3")
                }
              >
                <Share2 className="h-3.5 w-3.5" /> 관계맵
              </button>
              <button
                type="button"
                onClick={() => setView("list")}
                aria-pressed={view === "list"}
                className={
                  "inline-flex items-center gap-1 px-2 py-1 transition-colors " +
                  (view === "list"
                    ? "bg-sky-100 font-medium text-sky-800 dark:bg-sky-500/20 dark:text-sky-200"
                    : "text-neutral-600 hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-surface-3")
                }
              >
                <List className="h-3.5 w-3.5" /> 목록
              </button>
            </div>
            <span
              className="inline-flex cursor-help items-center gap-1 text-[11px] text-neutral-400 dark:text-neutral-500"
              title={
                "선정 기준 — 같은 제품 > 같은 벤더 > 공통 약점(공격 유형) > 심각도(CVSS) 근접 > 최신 순으로 " +
                "가중 점수를 매겨 상위 8건을 보여줍니다. 각 항목 오른쪽의 회색 배지가 그 항목이 선정된 근거입니다."
              }
            >
              <Info className="h-3.5 w-3.5" /> 선정 기준
            </span>
          </div>
        </div>
        <p className="text-[11px] leading-relaxed text-neutral-500 dark:text-neutral-500">
          같은 제품·벤더·약점 유형과 심각도(CVSS) 근접도를 가중 점수화해 가까운 순으로 정렬했습니다.
        </p>
      </CardHeader>
      <CardContent>
        {view === "graph" ? (
          <RelatedCvesGraph centerId={cveId} items={items} />
        ) : (
          <ul className="divide-y divide-neutral-100 dark:divide-neutral-800/60">
          {items.map((it) => (
            <li key={it.cveId}>
              <Link
                href={`/cve/${it.cveId}` as Route}
                className="flex items-start gap-2 rounded-md px-1 py-2 transition-colors hover:bg-neutral-50 dark:hover:bg-surface-2"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[12px] font-semibold text-neutral-900 dark:text-neutral-100">
                      {it.cveId}
                    </span>
                    {it.severity && <SeverityBadge severity={it.severity} score={it.cvssScore ?? undefined} />}
                    {it.kevListed && (
                      <span className="inline-flex items-center gap-0.5 rounded-full bg-rose-100 px-1.5 py-0.5 text-[9px] font-semibold text-rose-800 dark:bg-rose-500/15 dark:text-rose-200">
                        <Flame className="h-2.5 w-2.5" />
                        KEV
                      </span>
                    )}
                    <span className="rounded-full bg-surface-2 px-1.5 py-0.5 text-[10px] text-neutral-500">
                      {it.reason}
                    </span>
                  </div>
                  <p className="mt-0.5 line-clamp-1 text-[11px] leading-snug text-neutral-600 dark:text-neutral-400">
                    {it.title}
                  </p>
                </div>
              </Link>
            </li>
          ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
