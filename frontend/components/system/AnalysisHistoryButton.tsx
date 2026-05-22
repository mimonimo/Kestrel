"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { History, Loader2, Sparkles, Trash2, X } from "lucide-react";
import { useIsFetching, useQueryClient } from "@tanstack/react-query";

import {
  clearAnalysisHistory,
  deleteAnalysisHistoryEntry,
  readAnalysisHistory,
  type AnalysisHistoryEntry,
} from "@/lib/analysis-history";
import { cn } from "@/lib/utils";

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

export function AnalysisHistoryButton() {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [entries, setEntries] = useState<AnalysisHistoryEntry[]>([]);
  const popoverRef = useRef<HTMLDivElement | null>(null);
  const buttonRef = useRef<HTMLButtonElement | null>(null);

  // Cross-session live status — useIsFetching scoped to AiAnalysisPanel's
  // useQuery key. Increments while ANY CVE detail page has its analysis
  // request in flight. Survives navigation because the QueryClient is at
  // the root Provider.
  const runningCount = useIsFetching({
    queryKey: ["ai-analysis"],
    exact: false,
  });

  // Pull the specific CVE IDs currently in flight so the popover can
  // list them with a spinner. Re-derived on every render — cheap (the
  // cache holds at most ~50 entries) and react-query bumps the
  // useIsFetching counter on state change so we re-render automatically.
  const runningCveIds = useMemo<string[]>(() => {
    const all = qc.getQueryCache().findAll({ queryKey: ["ai-analysis"] });
    return all
      .filter((q) => q.state.fetchStatus === "fetching")
      .map((q) => (q.queryKey[1] as string | undefined) ?? "")
      .filter((id): id is string => !!id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runningCount, qc]);

  const refresh = useCallback(() => {
    setEntries(readAnalysisHistory());
  }, []);

  useEffect(() => {
    refresh();
    const onChange = () => refresh();
    window.addEventListener("kestrel:analysis-history-changed", onChange);
    window.addEventListener("storage", onChange);
    return () => {
      window.removeEventListener("kestrel:analysis-history-changed", onChange);
      window.removeEventListener("storage", onChange);
    };
  }, [refresh]);

  // Click-outside + ESC close
  useEffect(() => {
    if (!open) return;
    const id = window.setTimeout(() => {
      const onDown = (e: PointerEvent) => {
        const t = e.target as Node | null;
        if (!t) return;
        if (popoverRef.current?.contains(t)) return;
        if (buttonRef.current?.contains(t)) return;
        setOpen(false);
      };
      const onKey = (e: KeyboardEvent) => {
        if (e.key === "Escape") setOpen(false);
      };
      document.addEventListener("pointerdown", onDown, true);
      document.addEventListener("keydown", onKey);
      (window as unknown as { __ahCleanup?: () => void }).__ahCleanup = () => {
        document.removeEventListener("pointerdown", onDown, true);
        document.removeEventListener("keydown", onKey);
      };
    }, 0);
    return () => {
      window.clearTimeout(id);
      (window as unknown as { __ahCleanup?: () => void }).__ahCleanup?.();
    };
  }, [open]);

  const count = entries.length;
  const recentExcerpt = useMemo(() => entries.slice(0, 8), [entries]);
  const isRunning = runningCount > 0;

  // Render nothing when there's nothing to surface (no completed history
  // AND no in-flight analysis) — keeps the page footer uncluttered for
  // first-time users who haven't tried the AI feature yet.
  if (count === 0 && !isRunning && !open) return null;

  return (
    // Stack above the StatusBanner. StatusBanner uses fixed bottom-4
    // right-4 (sm:bottom-6 right-6) with a single anchor pill that's
    // ~36px tall. Put this group at bottom-16 (≈ 64px) so the two
    // float independently and never overlap.
    <div className="pointer-events-none fixed bottom-16 right-4 z-50 flex flex-col items-end gap-2 sm:bottom-[5.5rem] sm:right-6">
      {open && (
        <div
          ref={popoverRef}
          role="dialog"
          aria-label="AI 분석 기록"
          className="pointer-events-auto w-[min(92vw,360px)] overflow-hidden rounded-xl border border-neutral-200 bg-white shadow-2xl shadow-black/10 dark:border-neutral-700 dark:bg-surface-1 dark:shadow-black/50"
          onPointerDown={(e) => e.stopPropagation()}
        >
          <div className="flex items-center justify-between border-b border-neutral-200 bg-neutral-50 px-4 py-2.5 dark:border-neutral-800 dark:bg-surface-2">
            <div className="flex items-center gap-2 text-sm font-semibold text-neutral-900 dark:text-neutral-100">
              <Sparkles className="h-4 w-4 text-violet-600 dark:text-violet-400" />
              AI 분석 기록
            </div>
            <button
              type="button"
              onClick={() => setOpen(false)}
              aria-label="닫기"
              className="rounded-full p-1 text-neutral-500 hover:bg-neutral-200 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-surface-3 dark:hover:text-neutral-100"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="max-h-[60vh] overflow-y-auto">
            {runningCveIds.length > 0 && (
              <div className="border-b border-neutral-200 px-4 py-2 dark:border-neutral-800">
                <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-violet-700 dark:text-violet-300">
                  분석 중 {runningCveIds.length}건
                </div>
                <ul className="space-y-1">
                  {runningCveIds.map((cid) => (
                    <li key={cid}>
                      <Link
                        href={`/cve/${encodeURIComponent(cid)}` as never}
                        onClick={() => setOpen(false)}
                        className="flex items-center gap-2 rounded-lg px-2 py-1 text-[11px] text-neutral-900 transition-colors hover:bg-violet-50 dark:text-neutral-100 dark:hover:bg-violet-500/10"
                      >
                        <Loader2 className="h-3 w-3 animate-spin text-violet-600 dark:text-violet-400" />
                        <span className="font-mono">{cid}</span>
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {entries.length === 0 && runningCveIds.length === 0 ? (
              <p className="px-4 py-6 text-center text-xs text-neutral-600 dark:text-neutral-500">
                아직 실행한 AI 분석이 없습니다.
              </p>
            ) : entries.length === 0 ? null : (
              <ul className="divide-y divide-neutral-200 dark:divide-neutral-800">
                {recentExcerpt.map((e) => (
                  <li
                    key={e.cveId}
                    className="group flex items-start gap-2 px-4 py-2.5 hover:bg-neutral-50 dark:hover:bg-surface-2"
                  >
                    <Link
                      href={`/cve/${encodeURIComponent(e.cveId)}` as never}
                      onClick={() => setOpen(false)}
                      className="min-w-0 flex-1"
                    >
                      <div className="flex items-baseline justify-between gap-2">
                        <span className="font-mono text-[12px] font-semibold text-neutral-900 dark:text-neutral-100">
                          {e.cveId}
                        </span>
                        <span className="shrink-0 text-[10px] tabular-nums text-neutral-500 dark:text-neutral-500">
                          {formatAge(e.timestamp)}
                        </span>
                      </div>
                      <p className="mt-0.5 line-clamp-2 text-[11px] leading-snug text-neutral-700 dark:text-neutral-400">
                        {e.attackMethod}
                      </p>
                      <div className="mt-1 flex items-center gap-2 text-[10px] text-neutral-600 dark:text-neutral-500">
                        <span>페이로드 {e.payloadCount}</span>
                        <span>·</span>
                        <span>대응 {e.mitigationCount}</span>
                      </div>
                    </Link>
                    <button
                      type="button"
                      onClick={(ev) => {
                        ev.stopPropagation();
                        deleteAnalysisHistoryEntry(e.cveId);
                      }}
                      title="기록에서 제거"
                      className="invisible h-6 w-6 shrink-0 rounded-full text-neutral-500 hover:bg-neutral-200 hover:text-rose-700 group-hover:visible dark:text-neutral-500 dark:hover:bg-surface-3 dark:hover:text-rose-300"
                    >
                      <X className="mx-auto h-3 w-3" />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
          {(entries.length > 0 || runningCveIds.length > 0) && (
            <div className="flex items-center justify-between gap-2 border-t border-neutral-200 bg-neutral-50 px-4 py-2 text-[11px] dark:border-neutral-800 dark:bg-surface-0">
              <Link
                href={"/analysis" as never}
                onClick={() => setOpen(false)}
                className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-medium text-violet-700 hover:bg-violet-500/10 hover:text-violet-900 dark:text-violet-300 dark:hover:text-violet-200"
              >
                전체 기록 보기 →
              </Link>
              {entries.length > 0 && (
                <button
                  type="button"
                  onClick={() => {
                    if (confirm("모든 분석 기록을 지우시겠습니까?")) {
                      clearAnalysisHistory();
                    }
                  }}
                  className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-neutral-600 hover:bg-neutral-200 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-surface-3 dark:hover:text-neutral-100"
                >
                  <Trash2 className="h-3 w-3" />
                  전체 지우기
                </button>
              )}
            </div>
          )}
        </div>
      )}

      {/* Pill matches StatusBanner "상태 보기" geometry 1:1 — same gap-2,
          rounded-full, border, px-3.5 py-2, text-xs, shadow-lg, backdrop-blur,
          h-2 w-2 dot, h-4 w-4 icon. Single icon (no extra spinner) so width
          stays identical between idle and running states. */}
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "pointer-events-auto flex items-center gap-2 rounded-full border px-3.5 py-2 text-xs font-medium shadow-lg shadow-black/10 backdrop-blur transition-colors hover:bg-violet-500/25 active:scale-95 dark:shadow-black/30",
          isRunning
            ? "border-violet-500/40 bg-violet-500/15 text-violet-800 dark:text-violet-200"
            : "border-violet-500/30 bg-violet-500/10 text-violet-800 dark:bg-violet-500/10 dark:text-violet-200",
        )}
        aria-expanded={open}
        aria-haspopup="dialog"
        aria-label="AI 분석 기록 보기"
      >
        <span className="relative flex h-2 w-2">
          {isRunning && (
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-violet-400 opacity-60" />
          )}
          <span
            className={cn(
              "relative inline-flex h-2 w-2 rounded-full",
              isRunning ? "bg-violet-500" : "bg-violet-400",
            )}
          />
        </span>
        <History className="h-4 w-4" />
        <span>{isRunning ? "분석 중" : "분석 기록"}</span>
        {(isRunning ? runningCount : count) > 0 && (
          <span className="tabular-nums rounded-full bg-violet-500/25 px-1.5 py-0.5 text-[10px] font-semibold text-violet-800 dark:bg-violet-500/30 dark:text-violet-100">
            {isRunning ? runningCount : count}
          </span>
        )}
      </button>
    </div>
  );
}
