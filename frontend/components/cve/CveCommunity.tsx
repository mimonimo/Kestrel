"use client";

// CVE 상세에 붙는 "커뮤니티 분석" — 이 취약점에 대한 공개 분석(사람·🤖 에이전트)을
// 작성자 프로필 링크와 함께 보여줘 취약점 페이지를 커뮤니티와 연동한다.
// 각 항목 클릭 시 분석 본문(result_md)을 공용 모달로 펼쳐 보여 준다.
import Link from "next/link";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Users } from "lucide-react";

import { api } from "@/lib/api";
import { formatRelativeKo } from "@/lib/format";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { AuthorInline } from "@/components/community/AuthorInline";
import { AnalysisDetailModal } from "@/components/community/AnalysisDetailModal";

export function CveCommunity({ cveId }: { cveId: string }) {
  const q = useQuery({
    queryKey: ["cve-community-analyses", cveId],
    queryFn: () => api.listCveAnalyses(cveId),
    staleTime: 60_000,
  });
  // null = 닫힘. 클릭한 분석 id 를 담으면 모달이 본문을 lazy fetch.
  const [openId, setOpenId] = useState<string | null>(null);
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
            return (
              <li key={a.id}>
                <button
                  type="button"
                  onClick={() => setOpenId(a.id)}
                  className="-mx-2 block w-full rounded-lg px-2 py-2.5 text-left transition-colors hover:bg-neutral-50 dark:hover:bg-surface-2/60"
                >
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
                    {/* 작성자 링크 클릭은 모달을 열지 않고 프로필로 이동 */}
                    <span onClick={(e) => e.stopPropagation()} className="contents">
                      <AuthorInline
                        author={a.author}
                        className="font-medium text-neutral-800 dark:text-neutral-200"
                      />
                    </span>
                    {a.author.isAgent && (
                      <span className="inline-flex items-center gap-0.5 rounded-full bg-sky-100 px-1.5 py-0.5 text-[9px] font-semibold text-sky-700 dark:bg-sky-500/15 dark:text-sky-200">
                        🤖 {a.author.persona || "AI"}
                      </span>
                    )}
                    {a.title && <span className="text-neutral-500 dark:text-neutral-400">· {a.title}</span>}
                    <span className="ml-auto tabular-nums text-[10px] text-neutral-400">{formatRelativeKo(a.createdAt)}</span>
                  </div>
                  {/* 미리보기 — 파싱된 공격 방법이 없으면 본문 excerpt 로 폴백해
                      "빈 분석"처럼 보이지 않게 한다(정확성). */}
                  {(a.attackMethod || a.excerpt) && (
                    <p className="mt-1 line-clamp-2 text-[11px] leading-relaxed text-neutral-600 dark:text-neutral-400">
                      {a.attackMethod || a.excerpt}
                    </p>
                  )}
                  {/* 카운트는 실제 값이 있을 때만 — 0/0 은 파싱 한계라 표시하지 않음 */}
                  {(a.payloadCount > 0 || a.mitigationCount > 0) && (
                    <div className="mt-1 flex gap-2 text-[10px] text-neutral-400">
                      {a.payloadCount > 0 && <span>페이로드 {a.payloadCount}</span>}
                      {a.mitigationCount > 0 && <span>완화 {a.mitigationCount}</span>}
                    </div>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </CardContent>

      <AnalysisDetailModal
        analysisId={openId}
        summary={items.find((a) => a.id === openId) ?? null}
        onClose={() => setOpenId(null)}
      />
    </Card>
  );
}
