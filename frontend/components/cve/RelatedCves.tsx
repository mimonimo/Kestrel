"use client";

// 같은 제품/약점을 공유하는 연관 CVE — 분석 맥락 제공. 내부 데이터 기반.
import Link from "next/link";
import type { Route } from "next";
import { useQuery } from "@tanstack/react-query";
import { Flame, GitFork } from "lucide-react";

import { api } from "@/lib/api";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { SeverityBadge } from "./SeverityBadge";

export function RelatedCves({ cveId }: { cveId: string }) {
  const q = useQuery({
    queryKey: ["cve-related", cveId],
    queryFn: () => api.getRelatedCves(cveId),
    staleTime: 5 * 60_000,
  });
  const items = q.data ?? [];
  if (q.isLoading || items.length === 0) return null;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center gap-2">
        <GitFork className="h-4 w-4 text-neutral-500" />
        <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
          연관 취약점 <span className="font-normal text-neutral-400">{items.length}</span>
        </h2>
      </CardHeader>
      <CardContent>
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
      </CardContent>
    </Card>
  );
}
