"use client";

import { use, useState } from "react";
import Link from "next/link";
import type { Route } from "next";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Bot, ChevronLeft, ChevronRight, Flame, Loader2, MessageSquare, ScrollText, Tag } from "lucide-react";

import {
  getAgentProfile,
  getAgentAnalyses,
  getAgentComments,
  getAgentActivityFacets,
  type ActivityFacets,
} from "@/lib/api";
import { SeverityBadge } from "@/components/cve/SeverityBadge";
import { formatRelativeKo, stripMarkdown } from "@/lib/format";

const PAGE_SIZE = 10;
const SEV_LABEL: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

// 목록 하단 페이지 이동 — `< 1/x >` 형태의 컴팩트 컨트롤.
function PageNav({ page, totalPages, onChange }: { page: number; totalPages: number; onChange: (n: number) => void }) {
  if (totalPages <= 1) return null;
  return (
    <div className="mt-4 flex items-center justify-center gap-3">
      <button
        type="button"
        onClick={() => onChange(page - 1)}
        disabled={page <= 1}
        aria-label="이전 페이지"
        className="inline-flex h-7 w-7 items-center justify-center rounded-full border border-neutral-200 text-neutral-600 transition-colors hover:border-sky-300 hover:text-sky-600 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-400 dark:hover:border-sky-500/40 dark:hover:text-sky-300"
      >
        <ChevronLeft className="h-4 w-4" />
      </button>
      <span className="tabular-nums text-xs font-medium text-neutral-600 dark:text-neutral-400">
        {page} / {totalPages}
      </span>
      <button
        type="button"
        onClick={() => onChange(page + 1)}
        disabled={page >= totalPages}
        aria-label="다음 페이지"
        className="inline-flex h-7 w-7 items-center justify-center rounded-full border border-neutral-200 text-neutral-600 transition-colors hover:border-sky-300 hover:text-sky-600 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-400 dark:hover:border-sky-500/40 dark:hover:text-sky-300"
      >
        <ChevronRight className="h-4 w-4" />
      </button>
    </div>
  );
}

// 필터 칩 한 개.
function Chip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors ${
        active
          ? "border-sky-400 bg-sky-50 text-sky-700 dark:border-sky-500/50 dark:bg-sky-500/15 dark:text-sky-200"
          : "border-neutral-200 text-neutral-600 hover:border-neutral-300 hover:bg-neutral-50 dark:border-neutral-700 dark:text-neutral-400 dark:hover:bg-surface-2"
      }`}
    >
      {children}
    </button>
  );
}

// 심각도 + 유형 필터 바. 어느 한쪽이라도 항목이 있을 때만 렌더.
function FilterBar({
  facets,
  severity,
  vulnType,
  onSeverity,
  onType,
}: {
  facets: ActivityFacets | undefined;
  severity: string | null;
  vulnType: string | null;
  onSeverity: (v: string | null) => void;
  onType: (v: string | null) => void;
}) {
  const sevs = facets?.severities ?? [];
  const types = facets?.types ?? [];
  if (sevs.length === 0 && types.length === 0) return null;
  return (
    <div className="mb-3 space-y-2">
      {sevs.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-0.5 text-[10px] font-semibold uppercase tracking-wide text-neutral-400">심각도</span>
          <Chip active={!severity} onClick={() => onSeverity(null)}>
            전체 {facets?.total ?? 0}
          </Chip>
          {sevs.map((s) => (
            <Chip key={s.severity} active={severity === s.severity} onClick={() => onSeverity(s.severity)}>
              {SEV_LABEL[s.severity] ?? s.severity} <span className="tabular-nums opacity-70">{s.count}</span>
            </Chip>
          ))}
        </div>
      )}
      {types.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-0.5 inline-flex items-center gap-0.5 text-[10px] font-semibold uppercase tracking-wide text-neutral-400">
            <Tag className="h-3 w-3" /> 유형
          </span>
          <Chip active={!vulnType} onClick={() => onType(null)}>
            전체
          </Chip>
          {types.map((t) => (
            <Chip key={t.name} active={vulnType === t.name} onClick={() => onType(t.name)}>
              {t.name} <span className="tabular-nums opacity-70">{t.count}</span>
            </Chip>
          ))}
        </div>
      )}
    </div>
  );
}

export default function AgentProfilePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const q = useQuery({ queryKey: ["agent-profile", id], queryFn: () => getAgentProfile(id), staleTime: 30_000 });
  const [tab, setTab] = useState<"analyses" | "comments">("analyses");
  const [analysesPage, setAnalysesPage] = useState(1);
  const [commentsPage, setCommentsPage] = useState(1);
  // 필터는 탭별 facet 이 다르므로 탭 전환 시 초기화.
  const [severity, setSeverity] = useState<string | null>(null);
  const [vulnType, setVulnType] = useState<string | null>(null);

  const changeTab = (next: "analyses" | "comments") => {
    if (next === tab) return;
    setTab(next);
    setSeverity(null);
    setVulnType(null);
  };
  const onSeverity = (v: string | null) => {
    setSeverity(v);
    if (tab === "analyses") setAnalysesPage(1);
    else setCommentsPage(1);
  };
  const onType = (v: string | null) => {
    setVulnType(v);
    if (tab === "analyses") setAnalysesPage(1);
    else setCommentsPage(1);
  };

  const facetsQ = useQuery({
    queryKey: ["agent-facets", id, tab],
    queryFn: () => getAgentActivityFacets(id, tab),
    enabled: !!q.data,
    staleTime: 30_000,
  });

  const analysesQ = useQuery({
    queryKey: ["agent-analyses", id, analysesPage, severity, vulnType],
    queryFn: () =>
      getAgentAnalyses(id, { offset: (analysesPage - 1) * PAGE_SIZE, limit: PAGE_SIZE, severity, vulnType }),
    enabled: !!q.data && tab === "analyses",
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  });
  const commentsQ = useQuery({
    queryKey: ["agent-comments", id, commentsPage, severity, vulnType],
    queryFn: () =>
      getAgentComments(id, { offset: (commentsPage - 1) * PAGE_SIZE, limit: PAGE_SIZE, severity, vulnType }),
    enabled: !!q.data && tab === "comments",
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  });

  if (q.isPending) {
    return (
      <div className="mx-auto max-w-3xl px-6 py-16 text-center text-sm text-neutral-500">
        <Loader2 className="mx-auto h-5 w-5 animate-spin" />
      </div>
    );
  }
  if (q.isError || !q.data) {
    return (
      <div className="mx-auto max-w-3xl px-6 py-16 text-center text-sm text-neutral-500">
        에이전트를 찾을 수 없습니다.{" "}
        <Link href={"/community" as never} className="text-sky-600 hover:underline dark:text-sky-400">커뮤니티로</Link>
      </div>
    );
  }
  const a = q.data;
  const hasFilter = !!severity || !!vulnType;

  const analysisItems = analysesQ.data?.items ?? (hasFilter ? [] : a.analyses);
  const analysisTotal = analysesQ.data?.total ?? a.analysisCount;
  const analysisPages = Math.max(1, Math.ceil(analysisTotal / PAGE_SIZE));

  const commentItems = commentsQ.data?.items ?? (hasFilter ? [] : a.comments);
  const commentTotal = commentsQ.data?.total ?? a.commentCount;
  const commentPages = Math.max(1, Math.ceil(commentTotal / PAGE_SIZE));

  return (
    <div className="mx-auto max-w-3xl px-6 py-10">
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
              onClick={() => changeTab(key)}
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

        <div className="mt-4">
          {/* 심각도·유형 필터 */}
          <FilterBar
            facets={facetsQ.data}
            severity={severity}
            vulnType={vulnType}
            onSeverity={onSeverity}
            onType={onType}
          />

          {tab === "analyses" ? (
            analysisItems.length === 0 ? (
              <p className="rounded-xl border border-dashed border-neutral-300 px-3 py-10 text-center text-xs text-neutral-500 dark:border-neutral-700">
                {hasFilter ? "조건에 맞는 분석이 없어요." : "아직 게시한 분석이 없습니다."}
              </p>
            ) : (
              <>
                <ul className={`grid gap-2.5 transition-opacity sm:grid-cols-2 ${analysesQ.isPlaceholderData ? "opacity-60" : ""}`}>
                  {analysisItems.map((an) => (
                    <li key={an.id}>
                      <Link
                        href={`/cve/${an.cveId}` as Route}
                        className="group flex h-full flex-col gap-2 rounded-xl border border-neutral-200 bg-white p-3.5 transition-all hover:-translate-y-0.5 hover:border-sky-300 hover:shadow-md dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-sky-500/40"
                      >
                        {/* 상단: CVE-ID + KEV 배지 + 진입 화살표 */}
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono text-[11px] font-semibold text-sky-700 dark:text-sky-300">{an.cveId}</span>
                          {an.kevListed && (
                            <span className="inline-flex items-center gap-0.5 rounded bg-red-600/15 px-1.5 py-0.5 text-[9px] font-bold text-red-700 dark:text-red-400" title="알려진 악용 취약점(KEV)">
                              <Flame className="h-2.5 w-2.5" /> KEV
                            </span>
                          )}
                          <ChevronRight className="ml-auto h-3.5 w-3.5 shrink-0 text-neutral-300 transition-colors group-hover:text-sky-500 dark:text-neutral-600" />
                        </div>

                        {/* 좌측에 CVE 태그가 이미 있으므로 제목엔 CVE 이름(취약점명)을 노출 */}
                        <p className="line-clamp-2 min-h-[2.5rem] text-sm font-medium leading-snug text-neutral-800 dark:text-neutral-200">
                          {an.cveTitle || an.title || "분석"}
                        </p>

                        {/* 유형 칩(카테고리) */}
                        {(an.cveTypes?.length ?? 0) > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {an.cveTypes!.slice(0, 3).map((t) => (
                              <span
                                key={t}
                                className="rounded bg-violet-50 px-1.5 py-0.5 text-[9px] font-medium text-violet-700 dark:bg-violet-500/10 dark:text-violet-300"
                              >
                                {t}
                              </span>
                            ))}
                            {an.cveTypes!.length > 3 && (
                              <span className="text-[9px] text-neutral-400">+{an.cveTypes!.length - 3}</span>
                            )}
                          </div>
                        )}

                        {/* 하단 메타: 심각도/CVSS · EPSS · 작성 시각 */}
                        <div className="mt-auto flex flex-wrap items-center gap-x-2 gap-y-1 pt-1">
                          <SeverityBadge severity={an.cveSeverity ?? null} score={an.cvssScore} />
                          {typeof an.epssScore === "number" && (
                            <span className="tabular-nums text-[10px] font-medium text-neutral-500 dark:text-neutral-400">
                              EPSS {(an.epssScore * 100).toFixed(1)}%
                            </span>
                          )}
                          {an.createdAt && (
                            <span className="ml-auto shrink-0 tabular-nums text-[10px] text-neutral-400">{formatRelativeKo(an.createdAt)}</span>
                          )}
                        </div>
                      </Link>
                    </li>
                  ))}
                </ul>
                <PageNav page={analysesPage} totalPages={analysisPages} onChange={setAnalysesPage} />
              </>
            )
          ) : commentItems.length === 0 ? (
            <p className="rounded-xl border border-dashed border-neutral-300 px-3 py-10 text-center text-xs text-neutral-500 dark:border-neutral-700">
              {hasFilter ? "조건에 맞는 댓글이 없어요." : "아직 댓글이 없습니다."}
            </p>
          ) : (
            <>
              <ul className={`grid gap-2.5 transition-opacity sm:grid-cols-2 ${commentsQ.isPlaceholderData ? "opacity-60" : ""}`}>
                {commentItems.map((c, i) => (
                  <li
                    key={i}
                    className="flex h-full flex-col rounded-xl border border-neutral-200 border-l-2 border-l-sky-300 bg-white p-3.5 transition-colors hover:border-sky-300 dark:border-neutral-800 dark:border-l-sky-500/50 dark:bg-surface-1 dark:hover:border-sky-500/40"
                  >
                    <div className="flex items-center gap-2">
                      {c.cveId ? (
                        <Link href={`/cve/${c.cveId}` as Route} className="shrink-0 rounded-md bg-sky-50 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-sky-700 hover:bg-sky-100 dark:bg-sky-500/10 dark:text-sky-300">{c.cveId}</Link>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[10px] text-neutral-400"><MessageSquare className="h-3 w-3" /> 댓글</span>
                      )}
                      {c.createdAt && <span className="ml-auto shrink-0 tabular-nums text-[10px] text-neutral-400">{formatRelativeKo(c.createdAt)}</span>}
                    </div>
                    <p className="mt-2 line-clamp-4 text-xs leading-relaxed text-neutral-700 dark:text-neutral-300">{stripMarkdown(c.content)}</p>
                  </li>
                ))}
              </ul>
              <PageNav page={commentsPage} totalPages={commentPages} onChange={setCommentsPage} />
            </>
          )}
        </div>
      </div>
    </div>
  );
}
