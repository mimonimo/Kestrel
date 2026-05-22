"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { History, Sparkles, Trash2, X } from "lucide-react";

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
  const [open, setOpen] = useState(false);
  const [entries, setEntries] = useState<AnalysisHistoryEntry[]>([]);
  const popoverRef = useRef<HTMLDivElement | null>(null);
  const buttonRef = useRef<HTMLButtonElement | null>(null);

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

  // Render nothing until at least one analysis exists — the button has
  // no value before then and would clutter every page footer.
  if (count === 0 && !open) return null;

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
            {entries.length === 0 ? (
              <p className="px-4 py-6 text-center text-xs text-neutral-600 dark:text-neutral-500">
                아직 실행한 AI 분석이 없습니다.
              </p>
            ) : (
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
          {entries.length > 0 && (
            <div className="flex items-center justify-between gap-2 border-t border-neutral-200 bg-neutral-50 px-4 py-2 text-[11px] dark:border-neutral-800 dark:bg-surface-0">
              <span className="tabular-nums text-neutral-600 dark:text-neutral-500">
                총 {entries.length}건
                {entries.length > recentExcerpt.length &&
                  ` · ${recentExcerpt.length}개 표시`}
              </span>
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
            </div>
          )}
        </div>
      )}

      <button
        ref={buttonRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "pointer-events-auto flex items-center gap-2 rounded-full border border-violet-500/40 bg-violet-500/15 px-3.5 py-2 text-xs font-medium text-violet-800 shadow-lg shadow-violet-500/20 backdrop-blur transition-all duration-150 hover:bg-violet-500/25 active:scale-95 dark:text-violet-200",
        )}
        aria-expanded={open}
        aria-haspopup="dialog"
        aria-label="AI 분석 기록 보기"
      >
        <History className="h-4 w-4" />
        <span>분석 기록</span>
        {count > 0 && (
          <span className="tabular-nums rounded-full bg-violet-500/30 px-1.5 py-0.5 text-[10px] font-semibold text-violet-900 dark:bg-violet-500/40 dark:text-violet-50">
            {count}
          </span>
        )}
      </button>
    </div>
  );
}
