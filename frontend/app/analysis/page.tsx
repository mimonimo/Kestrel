"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { useIsFetching, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CheckSquare,
  ClipboardList,
  Clock,
  GitCompare,
  Loader2,
  MessageSquare,
  Search,
  Sparkles,
  Square,
  Star,
  Trash2,
  X,
} from "lucide-react";

import { api, type CompareResponse, type Ticket, type TicketStatus } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  clearAnalysisHistory,
  deleteAnalysisHistoryEntry,
  readAnalysisHistory,
  type AnalysisHistoryEntry,
} from "@/lib/analysis-history";
import { useBookmarks } from "@/lib/bookmarks";
import { useCommentHistory } from "@/lib/comment-history";
import { cn } from "@/lib/utils";

type TabKey = "analysis" | "compare" | "bookmarks" | "tickets" | "comments";

interface TabDef {
  key: TabKey;
  label: string;
  icon: typeof Sparkles;
}

const TABS: TabDef[] = [
  { key: "analysis", label: "AI 분석", icon: Sparkles },
  { key: "compare", label: "패턴 비교", icon: GitCompare },
  { key: "bookmarks", label: "즐겨찾기", icon: Star },
  { key: "tickets", label: "검토", icon: ClipboardList },
  { key: "comments", label: "댓글", icon: MessageSquare },
];

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

export default function AnalysisPage() {
  const [tab, setTab] = useState<TabKey>("analysis");

  return (
    <div className="mx-auto max-w-5xl px-6 py-10">
      <header className="mb-4 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-neutral-900 dark:text-neutral-100">AI 분석</h1>
          <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-500">
            분석 기록, 패턴 비교, 즐겨찾기, 대응 검토, 작성한 댓글을 한 곳에서 관리합니다.
          </p>
        </div>
      </header>

      {/* Tab strip — pill-segmented control matching dashboard period control */}
      <nav className="mb-6 inline-flex rounded-full border border-neutral-200 bg-white p-1 dark:border-neutral-800 dark:bg-surface-1">
        {TABS.map(({ key, label, icon: Icon }) => {
          const active = tab === key;
          return (
            <button
              key={key}
              type="button"
              onClick={() => setTab(key)}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-full px-3.5 py-1.5 text-xs font-medium transition-all duration-150 active:scale-95",
                active
                  ? "bg-sky-100 text-sky-800 shadow-sm dark:bg-sky-500/20 dark:text-sky-200"
                  : "text-neutral-600 hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-surface-2 dark:hover:text-neutral-100",
              )}
              aria-pressed={active}
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
            </button>
          );
        })}
      </nav>

      {tab === "analysis" && <AnalysisTab />}
      {tab === "compare" && <CompareTab />}
      {tab === "bookmarks" && <BookmarksTab />}
      {tab === "tickets" && <TicketsTab />}
      {tab === "comments" && <CommentsTab />}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
// Tab 1 — AI 분석
// ──────────────────────────────────────────────────────────────────────

function AnalysisTab() {
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

  const runningCount = useIsFetching({ queryKey: ["ai-analysis"], exact: false });
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
      (e) => e.cveId.toLowerCase().includes(q) || e.attackMethod.toLowerCase().includes(q),
    );
  }, [entries, query]);

  return (
    <>
      {/* Running */}
      {runningCveIds.length > 0 && (
        <section className="mb-4 rounded-xl border border-violet-500/30 bg-violet-500/5 p-4">
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

      {/* Search + clear */}
      {entries.length > 0 && (
        <div className="mb-4 flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-neutral-500" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="CVE ID 또는 공격 기법 본문으로 검색"
              className="pl-9"
            />
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              if (confirm("저장된 분석 기록을 모두 삭제할까요?")) clearAnalysisHistory();
            }}
            className="border-rose-300 text-rose-700 hover:bg-rose-50 dark:border-rose-900/50 dark:text-rose-300 dark:hover:bg-rose-950/40"
          >
            <Trash2 className="mr-1 h-3.5 w-3.5" />
            전체 지우기
          </Button>
        </div>
      )}

      {entries.length === 0 ? (
        <EmptyState
          icon={Sparkles}
          title="아직 분석한 CVE 가 없어요"
          hint="CVE 상세 페이지에서 AI 심층 분석을 실행하면 결과가 여기에 누적됩니다."
        />
      ) : filtered.length === 0 ? (
        <NoMatch />
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
                      <Chip title={formatFull(e.timestamp)}>
                        <Clock className="h-3 w-3" />
                        {formatAge(e.timestamp)}
                      </Chip>
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
                  <RemoveButton onClick={() => deleteAnalysisHistoryEntry(e.cveId)} />
                </div>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

// ──────────────────────────────────────────────────────────────────────
// Tab 2 — 패턴 비교 (2~5개 CVE 동시 분석)
// ──────────────────────────────────────────────────────────────────────

function CompareTab() {
  const [entries, setEntries] = useState<AnalysisHistoryEntry[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [result, setResult] = useState<CompareResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

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

  const toggle = (id: string) => {
    setResult(null);
    setError(null);
    setSelected((prev) => {
      if (prev.includes(id)) return prev.filter((x) => x !== id);
      if (prev.length >= 5) return prev;
      return [...prev, id];
    });
  };

  const runCompare = async () => {
    if (selected.length < 2 || selected.length > 5) return;
    setPending(true);
    setError(null);
    setResult(null);
    try {
      const res = await api.compareCves(selected);
      setResult(res);
    } catch (e) {
      setError((e as Error).message || "비교 분석에 실패했어요.");
    } finally {
      setPending(false);
    }
  };

  return (
    <>
      <section className="mb-4 rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-surface-1">
        <header className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
              비교할 CVE 선택 (2 – 5개)
            </h2>
            <p className="mt-0.5 text-[11px] text-neutral-600 dark:text-neutral-500">
              여러 CVE 의 공통 공격 패턴 · 차이점 · 통합 완화 전략을 한 번에 도출합니다.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] tabular-nums text-neutral-600 dark:text-neutral-400">
              {selected.length} / 5
            </span>
            <Button
              type="button"
              size="sm"
              disabled={selected.length < 2 || pending}
              onClick={runCompare}
              className="rounded-full bg-violet-600 text-white hover:bg-violet-700 disabled:opacity-50 dark:bg-violet-500 dark:hover:bg-violet-400"
            >
              {pending ? (
                <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
              ) : (
                <GitCompare className="mr-1 h-3.5 w-3.5" />
              )}
              비교 분석 실행
            </Button>
          </div>
        </header>
        {entries.length === 0 ? (
          <p className="rounded-md border border-dashed border-neutral-300 bg-neutral-50 p-4 text-center text-[12px] text-neutral-600 dark:border-neutral-700 dark:bg-surface-2 dark:text-neutral-400">
            아직 분석한 CVE 가 없어 비교 대상이 비어 있습니다. CVE 상세에서 AI 분석을 먼저 실행해 주세요.
          </p>
        ) : (
          <ul className="max-h-72 space-y-1 overflow-y-auto pr-1">
            {entries.map((e) => {
              const checked = selected.includes(e.cveId);
              const disabled = !checked && selected.length >= 5;
              return (
                <li key={e.cveId}>
                  <button
                    type="button"
                    onClick={() => toggle(e.cveId)}
                    disabled={disabled}
                    className={cn(
                      "flex w-full items-start gap-2 rounded-md px-2 py-1.5 text-left transition-colors",
                      checked
                        ? "bg-violet-50 ring-1 ring-violet-300 dark:bg-violet-500/10 dark:ring-violet-500/40"
                        : "hover:bg-neutral-50 dark:hover:bg-surface-2",
                      disabled && "cursor-not-allowed opacity-40",
                    )}
                  >
                    {checked ? (
                      <CheckSquare className="mt-0.5 h-3.5 w-3.5 shrink-0 text-violet-600 dark:text-violet-400" />
                    ) : (
                      <Square className="mt-0.5 h-3.5 w-3.5 shrink-0 text-neutral-400 dark:text-neutral-600" />
                    )}
                    <div className="min-w-0 flex-1">
                      <div className="flex items-baseline justify-between gap-2">
                        <span className="font-mono text-[12px] font-semibold text-neutral-900 dark:text-neutral-100">
                          {e.cveId}
                        </span>
                        <span className="shrink-0 text-[10px] text-neutral-500 dark:text-neutral-500">
                          {formatAge(e.timestamp)}
                        </span>
                      </div>
                      <p className="mt-0.5 line-clamp-1 text-[11px] text-neutral-700 dark:text-neutral-400">
                        {e.attackMethod}
                      </p>
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
        {selected.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-1.5 border-t border-neutral-200 pt-3 dark:border-neutral-800">
            {selected.map((id) => (
              <span
                key={id}
                className="inline-flex items-center gap-1 rounded-full bg-violet-100 px-2 py-0.5 font-mono text-[10px] text-violet-800 dark:bg-violet-500/20 dark:text-violet-200"
              >
                {id}
                <button
                  type="button"
                  onClick={() => toggle(id)}
                  className="rounded-full hover:bg-violet-200 dark:hover:bg-violet-500/40"
                  aria-label={`${id} 제거`}
                >
                  <X className="h-2.5 w-2.5" />
                </button>
              </span>
            ))}
          </div>
        )}
      </section>

      {error && (
        <section className="mb-4 rounded-md border border-rose-300 bg-rose-50 p-3 text-[12px] text-rose-800 dark:border-rose-500/40 dark:bg-rose-500/10 dark:text-rose-200">
          {error}
        </section>
      )}

      {result && (
        <section className="space-y-4 rounded-xl border border-violet-300 bg-violet-50/50 p-4 dark:border-violet-500/40 dark:bg-violet-500/5">
          <header className="flex items-center gap-2 text-sm font-semibold text-violet-900 dark:text-violet-200">
            <Sparkles className="h-4 w-4" />
            비교 분석 결과
          </header>
          <div>
            <h3 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-neutral-600 dark:text-neutral-400">
              핵심 요약
            </h3>
            <p className="whitespace-pre-line text-sm leading-relaxed text-neutral-800 dark:text-neutral-200">
              {result.summary}
            </p>
          </div>
          <div>
            <h3 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-neutral-600 dark:text-neutral-400">
              공통 공격 패턴
            </h3>
            <p className="whitespace-pre-line text-sm leading-relaxed text-neutral-800 dark:text-neutral-200">
              {result.commonPattern}
            </p>
          </div>
          {result.differences.length > 0 && (
            <div>
              <h3 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-neutral-600 dark:text-neutral-400">
                차이점 ({result.differences.length})
              </h3>
              <ul className="space-y-1.5 text-sm text-neutral-800 dark:text-neutral-200">
                {result.differences.map((d, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="text-violet-600 dark:text-violet-400">·</span>
                    <span className="whitespace-pre-line">{d}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {result.sharedMitigations.length > 0 && (
            <div>
              <h3 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-neutral-600 dark:text-neutral-400">
                통합 완화 전략 ({result.sharedMitigations.length})
              </h3>
              <ol className="space-y-1.5 text-sm text-neutral-800 dark:text-neutral-200">
                {result.sharedMitigations.map((m, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="font-semibold text-violet-700 dark:text-violet-300">
                      {i + 1}.
                    </span>
                    <span className="whitespace-pre-line">{m}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
          {result.perCveNotes.length > 0 && (
            <div>
              <h3 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-neutral-600 dark:text-neutral-400">
                CVE 별 메모
              </h3>
              <ul className="space-y-1.5 text-sm">
                {result.perCveNotes.map((n) => (
                  <li
                    key={n.cveId}
                    className="rounded-md bg-white/60 p-2 dark:bg-surface-1/60"
                  >
                    <Link
                      href={`/cve/${encodeURIComponent(n.cveId)}` as never}
                      className="font-mono text-[12px] font-semibold text-violet-700 hover:underline dark:text-violet-300"
                    >
                      {n.cveId}
                    </Link>
                    <p className="mt-0.5 text-[12px] text-neutral-800 dark:text-neutral-300">
                      {n.note}
                    </p>
                  </li>
                ))}
              </ul>
            </div>
          )}
          <p className="text-[11px] text-neutral-500">
            ※ AI 생성 결과는 참고용이며, 실제 대응 전에는 반드시 전문가 검토가 필요합니다.
          </p>
        </section>
      )}
    </>
  );
}

// ──────────────────────────────────────────────────────────────────────
// Tab 3 — 즐겨찾기
// ──────────────────────────────────────────────────────────────────────

function BookmarksTab() {
  const { set, toggle, ready } = useBookmarks();
  const cveIds = useMemo(() => Array.from(set).sort(), [set]);
  const details = useQuery({
    queryKey: ["bookmark-details", cveIds],
    queryFn: () => api.batchVulnerabilities(cveIds),
    enabled: cveIds.length > 0,
    staleTime: 60_000,
  });

  if (!ready) return <LoadingRow />;
  if (cveIds.length === 0) {
    return (
      <EmptyState
        icon={Star}
        title="즐겨찾기한 CVE 가 아직 없어요"
        hint="CVE 카드나 상세 페이지의 별 아이콘으로 등록할 수 있습니다."
      />
    );
  }
  if (details.isLoading) return <LoadingRow />;

  const items = details.data ?? [];
  return (
    <ul className="space-y-3">
      {items.map((v) => (
        <li key={v.cveId}>
          <Link
            href={`/cve/${encodeURIComponent(v.cveId)}` as never}
            className="group block rounded-xl border border-neutral-200 bg-white p-4 transition-all duration-150 hover:-translate-y-0.5 hover:border-amber-300 hover:shadow-md hover:shadow-amber-500/10 active:translate-y-0 dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-amber-700"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="font-mono text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                    {v.cveId}
                  </span>
                  {v.severity && (
                    <Chip>
                      {v.severity.toUpperCase()}
                      {v.cvssScore && ` · ${v.cvssScore.toFixed(1)}`}
                    </Chip>
                  )}
                </div>
                <p className="mt-1.5 line-clamp-2 text-sm leading-relaxed text-neutral-700 dark:text-neutral-300">
                  {v.title}
                </p>
              </div>
              <button
                type="button"
                onClick={(ev) => {
                  ev.preventDefault();
                  ev.stopPropagation();
                  toggle(v.cveId);
                }}
                title="즐겨찾기 해제"
                className="invisible shrink-0 rounded-full p-1.5 text-amber-700 hover:bg-amber-50 group-hover:visible dark:text-amber-300 dark:hover:bg-amber-950/30"
              >
                <Star className="h-4 w-4 fill-current" />
              </button>
            </div>
          </Link>
        </li>
      ))}
    </ul>
  );
}

// ──────────────────────────────────────────────────────────────────────
// Tab 3 — 검토 (티켓)
// ──────────────────────────────────────────────────────────────────────

const TICKET_STATUS_LABEL: Record<TicketStatus, string> = {
  open: "열림",
  in_progress: "진행 중",
  resolved: "완료",
  ignored: "무시",
};

const TICKET_STATUS_STYLE: Record<TicketStatus, string> = {
  open: "bg-sky-100 text-sky-800 dark:bg-sky-500/20 dark:text-sky-200",
  in_progress: "bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-200",
  resolved: "bg-emerald-100 text-emerald-800 dark:bg-emerald-500/20 dark:text-emerald-200",
  ignored: "bg-neutral-200 text-neutral-700 dark:bg-neutral-700 dark:text-neutral-200",
};

function TicketsTab() {
  const q = useQuery({
    queryKey: ["tickets", "all"],
    queryFn: () => api.listTickets(),
    staleTime: 30_000,
  });

  if (q.isLoading) return <LoadingRow />;
  if (q.error) return <Err msg={(q.error as Error).message} />;
  const items: Ticket[] = q.data?.items ?? [];
  if (items.length === 0) {
    return (
      <EmptyState
        icon={ClipboardList}
        title="진행 중인 대응 항목이 없어요"
        hint="CVE 상세 페이지의 대응 상태에서 미확인·조치 중·완료를 지정하면 여기에 모입니다."
      />
    );
  }

  return (
    <ul className="space-y-3">
      {items.map((t) => (
        <li key={t.cveId}>
          <Link
            href={`/cve/${encodeURIComponent(t.cveId)}` as never}
            className="group block rounded-xl border border-neutral-200 bg-white p-4 transition-all duration-150 hover:-translate-y-0.5 hover:border-sky-300 hover:shadow-md hover:shadow-sky-500/10 active:translate-y-0 dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-sky-700"
          >
            <div className="flex items-start gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="font-mono text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                    {t.cveId}
                  </span>
                  <span
                    className={cn(
                      "inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium",
                      TICKET_STATUS_STYLE[t.status],
                    )}
                  >
                    {TICKET_STATUS_LABEL[t.status]}
                  </span>
                  <Chip>{formatAge(new Date(t.updatedAt).getTime())}</Chip>
                </div>
                {t.note && (
                  <p className="mt-1.5 line-clamp-2 text-sm leading-relaxed text-neutral-700 dark:text-neutral-300">
                    {t.note}
                  </p>
                )}
              </div>
            </div>
          </Link>
        </li>
      ))}
    </ul>
  );
}

// ──────────────────────────────────────────────────────────────────────
// Tab 4 — 댓글
// ──────────────────────────────────────────────────────────────────────

function CommentsTab() {
  const comments = useCommentHistory();
  if (comments.length === 0) {
    return (
      <EmptyState
        icon={MessageSquare}
        title="작성한 댓글이 아직 없어요"
        hint="커뮤니티 글이나 CVE 상세 페이지에 댓글을 남기면 여기에 함께 모입니다."
      />
    );
  }
  return (
    <ul className="space-y-3">
      {comments.map((c) => {
        const target = c.cveId
          ? `/cve/${encodeURIComponent(c.cveId)}`
          : c.postId
            ? `/community/${c.postId}`
            : "#";
        const targetLabel = c.cveId ? c.cveId : c.postId ? `커뮤니티 #${c.postId}` : "(연결 끊김)";
        return (
          <li key={c.id}>
            <Link
              href={target as never}
              className="group block rounded-xl border border-neutral-200 bg-white p-4 transition-all duration-150 hover:-translate-y-0.5 hover:border-emerald-300 hover:shadow-md hover:shadow-emerald-500/10 active:translate-y-0 dark:border-neutral-800 dark:bg-surface-1 dark:hover:border-emerald-700"
            >
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="font-mono text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                  {targetLabel}
                </span>
                <Chip title={formatFull(c.timestamp)}>
                  <Clock className="h-3 w-3" />
                  {formatAge(c.timestamp)}
                </Chip>
              </div>
              <p className="mt-1.5 line-clamp-2 text-sm leading-relaxed text-neutral-700 dark:text-neutral-300">
                {c.excerpt}
              </p>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

// ──────────────────────────────────────────────────────────────────────
// Shared bits
// ──────────────────────────────────────────────────────────────────────

function Chip({
  children,
  title,
}: {
  children: React.ReactNode;
  title?: string;
}) {
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full bg-neutral-100 px-1.5 py-0.5 text-[10px] tabular-nums text-neutral-700 dark:bg-surface-2 dark:text-neutral-400"
      title={title}
    >
      {children}
    </span>
  );
}

function RemoveButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={(ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        onClick();
      }}
      title="이 기록만 제거"
      className="invisible shrink-0 rounded-full p-1.5 text-neutral-500 hover:bg-rose-50 hover:text-rose-700 group-hover:visible dark:hover:bg-rose-950/40 dark:hover:text-rose-300"
    >
      <Trash2 className="h-3.5 w-3.5" />
    </button>
  );
}

function EmptyState({
  icon: Icon,
  title,
  hint,
}: {
  icon: typeof Sparkles;
  title: string;
  hint: string;
}) {
  return (
    <div className="rounded-xl border border-dashed border-neutral-300 bg-white px-6 py-12 text-center dark:border-neutral-800 dark:bg-surface-1">
      <Icon className="mx-auto mb-3 h-8 w-8 text-neutral-400 dark:text-neutral-600" />
      <h3 className="text-base font-semibold text-neutral-900 dark:text-neutral-100">{title}</h3>
      <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-500">{hint}</p>
    </div>
  );
}

function LoadingRow() {
  return (
    <div className="rounded-xl border border-neutral-200 bg-white px-4 py-6 text-center text-sm text-neutral-600 dark:border-neutral-800 dark:bg-surface-1 dark:text-neutral-500">
      <Loader2 className="mx-auto h-4 w-4 animate-spin" />
    </div>
  );
}

function NoMatch() {
  return (
    <p className="rounded-xl border border-neutral-200 bg-white px-4 py-6 text-center text-sm text-neutral-600 dark:border-neutral-800 dark:bg-surface-1 dark:text-neutral-500">
      검색 결과가 없습니다.
    </p>
  );
}

function Err({ msg }: { msg: string }) {
  return (
    <p className="rounded-xl border border-rose-300 bg-rose-50 px-4 py-3 text-sm text-rose-800 dark:border-rose-900/50 dark:bg-rose-950/30 dark:text-rose-200">
      로딩 실패: {msg}
    </p>
  );
}
