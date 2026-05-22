"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { useIsFetching, useQueryClient } from "@tanstack/react-query";
import {
  ArrowRight,
  Clock,
  History as HistoryIcon,
  Loader2,
  Search,
  Sparkles,
  Trash2,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  clearAnalysisHistory,
  deleteAnalysisHistoryEntry,
  readAnalysisHistory,
  type AnalysisHistoryEntry,
} from "@/lib/analysis-history";

function formatAge(epochMs: number): string {
  const diff = Date.now() - epochMs;
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "방금";
  if (mins < 60) return `${mins}분 전`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}시간 전`;
  const days = Math.floor(hours / 24);
  return `${days}일 전`;
}

function formatFull(epochMs: number): string {
  const d = new Date(epochMs);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export default function AnalysisHistoryPage() {
  const qc = useQueryClient();
  const [entries, setEntries] = useState<AnalysisHistoryEntry[]>([]);
  const [query, setQuery] = useState("");

  useEffect(() => {
    const sync = () => setEntries(readAnalysisHistory());
    sync();
    window.addEventListener("kestrel:analysis-history-changed", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("kestrel:analysis-history-changed", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  // Live in-flight analyses — same source as the floating button.
  const runningCount = useIsFetching({
    queryKey: ["ai-analysis"],
    exact: false,
  });
  const runningCveIds = useMemo<string[]>(() => {
    const all = qc.getQueryCache().findAll({ queryKey: ["ai-analysis"] });
    return all
      .filter((q) => q.state.fetchStatus === "fetching")
      .map((q) => (q.queryKey[1] as string | undefined) ?? "")
      .filter((id): id is string => !!id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runningCount, qc]);

  const filtered = useMemo(() => {
    if (!query.trim()) return entries;
    const q = query.toLowerCase();
    return entries.filter(
      (e) =>
        e.cveId.toLowerCase().includes(q) ||
        e.attackMethod.toLowerCase().includes(q),
    );
  }, [entries, query]);

  const totalPayloads = useMemo(
    () => entries.reduce((s, e) => s + e.payloadCount, 0),
    [entries],
  );
  const totalMitigations = useMemo(
    () => entries.reduce((s, e) => s + e.mitigationCount, 0),
    [entries],
  );

  return (
    <div className="mx-auto max-w-5xl px-6 py-10">
      <header className="mb-6 flex flex-wrap items-end justify-between gap-3 border-b border-neutral-200 pb-4 dark:border-neutral-800">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold text-neutral-900 dark:text-neutral-100">
            <Sparkles className="h-6 w-6 text-violet-600 dark:text-violet-400" />
            AI 분석 기록
          </h1>
          <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-500">
            지금까지 요청한 AI 심층 분석을 한 곳에서 확인합니다.
          </p>
        </div>
        {entries.length > 0 && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              if (confirm("모든 분석 기록을 지우시겠습니까?")) {
                clearAnalysisHistory();
              }
            }}
            className="border-rose-300 text-rose-700 hover:bg-rose-50 dark:border-rose-900/50 dark:text-rose-300 dark:hover:bg-rose-950/40"
          >
            <Trash2 className="mr-1 h-3.5 w-3.5" />
            전체 지우기
          </Button>
        )}
      </header>

      {/* Summary stats — 3 cards (총 분석, 페이로드, 대응 항목) */}
      <section className="mb-6 grid gap-3 sm:grid-cols-3">
        <StatCard label="총 분석" value={entries.length} icon={HistoryIcon} />
        <StatCard label="저장된 페이로드" value={totalPayloads} icon={Sparkles} />
        <StatCard label="저장된 대응 항목" value={totalMitigations} icon={ArrowRight} />
      </section>

      {/* Running analyses — violet card on top */}
      {runningCveIds.length > 0 && (
        <section className="mb-6 rounded-xl border border-violet-500/30 bg-violet-500/5 p-4">
          <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-violet-900 dark:text-violet-200">
            <Loader2 className="h-4 w-4 animate-spin" />
            진행 중 {runningCveIds.length}건
          </div>
          <ul className="flex flex-wrap gap-2">
            {runningCveIds.map((cid) => (
              <li key={cid}>
                <Link
                  href={`/cve/${encodeURIComponent(cid)}` as never}
                  className="inline-flex items-center gap-1.5 rounded-full bg-white/80 px-3 py-1 font-mono text-[11px] text-violet-900 transition-colors hover:bg-white dark:bg-surface-1/80 dark:text-violet-200 dark:hover:bg-surface-1"
                >
                  <Loader2 className="h-3 w-3 animate-spin" />
                  {cid}
                </Link>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Search filter */}
      {entries.length > 0 && (
        <div className="relative mb-4">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-neutral-500" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="CVE-ID 또는 공격기법 본문 검색"
            className="pl-9"
          />
        </div>
      )}

      {/* Empty state */}
      {entries.length === 0 ? (
        <div className="rounded-xl border border-dashed border-neutral-300 bg-white px-6 py-12 text-center dark:border-neutral-800 dark:bg-surface-1">
          <Sparkles className="mx-auto mb-3 h-8 w-8 text-violet-500/60" />
          <h3 className="text-base font-semibold text-neutral-900 dark:text-neutral-100">
            아직 분석한 CVE 가 없습니다
          </h3>
          <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-500">
            CVE 상세 페이지에서 <span className="font-medium text-violet-700 dark:text-violet-300">AI 심층 분석</span>{" "}
            을 요청하면 여기에 모입니다.
          </p>
        </div>
      ) : filtered.length === 0 ? (
        <p className="rounded-xl border border-neutral-200 bg-white px-4 py-6 text-center text-sm text-neutral-600 dark:border-neutral-800 dark:bg-surface-1 dark:text-neutral-500">
          검색 결과가 없습니다.
        </p>
      ) : (
        <ul className="space-y-3">
          {filtered.map((e) => (
            <li key={e.cveId}>
              <Link
                href={`/cve/${encodeURIComponent(e.cveId)}` as never}
                className="group block rounded-xl border border-neutral-200 bg-white p-4 transition-all duration-150 hover:-translate-y-0.5 hover:border-violet-300 hover:shadow-md hover:shadow-violet-500/10 active:translate-y-0 dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-violet-700"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-baseline gap-2">
                      <span className="font-mono text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                        {e.cveId}
                      </span>
                      <span
                        className="inline-flex items-center gap-1 rounded-full bg-neutral-100 px-1.5 py-0.5 text-[10px] tabular-nums text-neutral-700 dark:bg-surface-2 dark:text-neutral-400"
                        title={formatFull(e.timestamp)}
                      >
                        <Clock className="h-3 w-3" />
                        {formatAge(e.timestamp)}
                      </span>
                    </div>
                    <p className="mt-1.5 line-clamp-2 text-sm leading-relaxed text-neutral-700 dark:text-neutral-300">
                      {e.attackMethod}
                    </p>
                    <div className="mt-2 flex items-center gap-3 text-[11px] text-neutral-600 dark:text-neutral-500">
                      <span className="tabular-nums">페이로드 {e.payloadCount}</span>
                      <span>·</span>
                      <span className="tabular-nums">대응 {e.mitigationCount}</span>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={(ev) => {
                      ev.preventDefault();
                      ev.stopPropagation();
                      deleteAnalysisHistoryEntry(e.cveId);
                    }}
                    title="이 기록만 제거"
                    className="invisible shrink-0 rounded-full p-1.5 text-neutral-500 hover:bg-rose-50 hover:text-rose-700 group-hover:visible dark:hover:bg-rose-950/40 dark:hover:text-rose-300"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function StatCard({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: number;
  icon: typeof HistoryIcon;
}) {
  return (
    <div className="rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-surface-1">
      <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-neutral-600 dark:text-neutral-500">
        <Icon className="h-3.5 w-3.5" />
        {label}
      </div>
      <div className="mt-1 tabular-nums text-2xl font-bold text-neutral-900 dark:text-neutral-100">
        {value.toLocaleString("ko-KR")}
      </div>
    </div>
  );
}
