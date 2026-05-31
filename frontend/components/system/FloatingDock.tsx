"use client";

// One unified right-anchored dock that surfaces both system-health and
// AI-analysis activity behind a single pill + single popover. Used to
// be two separate floating buttons — which the user reported as
// awkward ("따로 누르는 게 좀 그렇다"). Now there's one entry point;
// the popover splits content into a 시스템 상태 section and an AI 분석
// section so neither piece of information is hidden.

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  BellOff,
  Info,
  Loader2,
  ShieldCheck,
  Sparkles,
  Trash2,
  X,
} from "lucide-react";
import { useIsFetching, useQueryClient } from "@tanstack/react-query";

import { useStatus } from "@/hooks/useStatus";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { useUserSetting } from "@/lib/user-settings";
import {
  readAnalysisHistory,
  syncAnalysisHistoryFromSummaries,
  type AnalysisHistoryEntry,
} from "@/lib/analysis-history";
import { useRunningAnalyses } from "@/lib/analysis-running";
import { markAllAnalysisSeen, markAnalysisSeen, useAnalysisSeen } from "@/lib/analysis-seen";
import type { IngestionSnapshot, Source, StatusReport } from "@/lib/types";
import { cn, timeAgo } from "@/lib/utils";

const SOURCE_LABEL: Record<Source, string> = {
  nvd: "NVD",
  exploit_db: "Exploit-DB",
  github_advisory: "GitHub Advisory",
  mitre: "MITRE",
};

const DISMISS_KEY = "kestrel:status-dismissed";

interface BannerLine {
  level: "warn" | "info";
  message: string;
}

function buildLines(
  s: StatusReport | undefined,
  clientKeys: { nvd: boolean; github: boolean },
): BannerLine[] {
  if (!s) return [];
  const lines: BannerLine[] = [];

  if (!s.db)
    lines.push({ level: "warn", message: "PostgreSQL에 연결할 수 없습니다. 데이터 표시가 제한됩니다." });
  if (!s.redis)
    lines.push({ level: "warn", message: "Redis에 연결할 수 없습니다. Rate limit 보호가 약화됩니다." });
  if (!s.meili)
    lines.push({
      level: "info",
      message: "Meilisearch가 응답하지 않아 PostgreSQL 전체 텍스트 검색으로 자동 전환되었습니다.",
    });

  if (!s.nvdKeyPresent && !clientKeys.nvd)
    lines.push({
      level: "info",
      message: "NVD API 키가 없어 5요청/30초로 제한됩니다. 설정 페이지에서 키를 등록하세요.",
    });
  if (!s.githubTokenPresent && !clientKeys.github)
    lines.push({
      level: "info",
      message: "GitHub Token이 없어 GitHub Advisory 수집이 제한됩니다. 설정 페이지에서 토큰을 등록하세요.",
    });

  s.ingestions.forEach((ing: IngestionSnapshot) => {
    if (ing.status === "failed") {
      lines.push({
        level: "warn",
        message: `${SOURCE_LABEL[ing.source]} 마지막 수집 실패${
          ing.errorMessage ? ` — ${ing.errorMessage.slice(0, 140)}` : ""
        }`,
      });
    }
  });

  return lines;
}

function signature(lines: BannerLine[]): string {
  return lines.map((l) => `${l.level}:${l.message}`).join("|");
}

function readDismissed(): string | null {
  if (typeof window === "undefined") return null;
  return sessionStorage.getItem(DISMISS_KEY);
}

function writeDismissed(sig: string | null) {
  if (typeof window === "undefined") return;
  if (sig === null) sessionStorage.removeItem(DISMISS_KEY);
  else sessionStorage.setItem(DISMISS_KEY, sig);
}

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

export function FloatingDock() {
  const { data: status } = useStatus();
  const { value: nvdApiKey } = useUserSetting("nvdApiKey");
  const { value: githubToken } = useUserSetting("githubToken");
  const qc = useQueryClient();

  const [open, setOpen] = useState(false);
  const [dismissedSig, setDismissedSig] = useState<string | null>(null);
  const [entries, setEntries] = useState<AnalysisHistoryEntry[]>([]);
  const seenSet = useAnalysisSeen();

  const popoverRef = useRef<HTMLDivElement | null>(null);
  const buttonRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    setDismissedSig(readDismissed());
  }, []);

  // useAuth 가 아래쪽 useEffect 에서도 필요해 위쪽으로 끌어올림.
  const { user: authUser } = useAuth();

  useEffect(() => {
    // 비로그인 상태에서는 활동센터에 분석 기록 노출 안 함 — localStorage 잔재
    // (이전 로그인 시 캐시) 도 가림 (PR 10-DJ).
    const refresh = () => setEntries(authUser ? readAnalysisHistory() : []);
    refresh();
    window.addEventListener("kestrel:analysis-history-changed", refresh);
    window.addEventListener("storage", refresh);
    return () => {
      window.removeEventListener("kestrel:analysis-history-changed", refresh);
      window.removeEventListener("storage", refresh);
    };
  }, [authUser]);

  // PR 10-DH — 활동센터도 backend /me/analyses 와 sync. AI 분석 탭과
  // 동일하게 다른 기기에서 한 분석도 dock 알림으로 노출.
  useEffect(() => {
    if (!authUser) return;
    let cancelled = false;
    api
      .listMyAnalyses({ limit: 100 })
      .then((res) => {
        if (cancelled) return;
        syncAnalysisHistoryFromSummaries(res.items);
        // 위 sync 가 dispatchEvent 까지 하니 setEntries 호출은 storage event
        // 핸들러가 알아서 처리 — 다만 같은 탭 race 보완용으로 한 번 더.
        setEntries(readAnalysisHistory());
      })
      .catch(() => {
        /* 401 등 — localStorage 단독 사용 */
      });
    return () => {
      cancelled = true;
    };
  }, [authUser?.id]);

  // ── Status state ─────────────────────────────────────────────────
  const clientKeys = useMemo(
    () => ({ nvd: !!nvdApiKey, github: !!githubToken }),
    [nvdApiKey, githubToken],
  );
  const lines = useMemo(() => buildLines(status, clientKeys), [status, clientKeys]);
  const sig = useMemo(() => signature(lines), [lines]);
  const warnCount = lines.filter((l) => l.level === "warn").length;
  const infoCount = lines.filter((l) => l.level === "info").length;
  const hasIssues = lines.length > 0;
  const isDismissed = dismissedSig !== null && dismissedSig === sig;

  const lastSync = useMemo(() => {
    if (!status) return null;
    const stamps = status.ingestions
      .map((i) => i.finishedAt)
      .filter((t): t is string => !!t)
      .sort();
    return stamps.length ? stamps[stamps.length - 1] : null;
  }, [status]);

  // ── Analysis state ───────────────────────────────────────────────
  const inFlight = useIsFetching({ queryKey: ["ai-analysis"], exact: false });
  const persistedRunning = useRunningAnalyses();

  const inFlightIds = useMemo<string[]>(() => {
    const all = qc.getQueryCache().findAll({ queryKey: ["ai-analysis"] });
    return all
      .filter((q) => q.state.fetchStatus === "fetching")
      .map((q) => (q.queryKey[1] as string | undefined) ?? "")
      .filter((id): id is string => !!id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inFlight, qc]);

  const runningCveIds = useMemo<string[]>(() => {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const id of inFlightIds) {
      if (!seen.has(id)) {
        seen.add(id);
        out.push(id);
      }
    }
    for (const e of persistedRunning) {
      if (!seen.has(e.cveId)) {
        seen.add(e.cveId);
        out.push(e.cveId);
      }
    }
    return out;
  }, [inFlightIds, persistedRunning]);

  const runningCount = runningCveIds.length;
  const isRunning = runningCount > 0;
  // unseen 만 활동 센터에 노출. 분석 기록 자체는 /analysis 탭에 유지.
  const unseenEntries = useMemo(
    () => entries.filter((e) => !seenSet.has(e.cveId)),
    [entries, seenSet],
  );
  const historyCount = unseenEntries.length;
  const recentExcerpt = useMemo(() => unseenEntries.slice(0, 8), [unseenEntries]);

  const close = useCallback(() => setOpen(false), []);

  const dismissStatus = useCallback(() => {
    writeDismissed(sig);
    setDismissedSig(sig);
  }, [sig]);

  const undismissStatus = useCallback(() => {
    writeDismissed(null);
    setDismissedSig(null);
  }, []);

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
      (window as unknown as { __dockCleanup?: () => void }).__dockCleanup = () => {
        document.removeEventListener("pointerdown", onDown, true);
        document.removeEventListener("keydown", onKey);
      };
    }, 0);
    return () => {
      window.clearTimeout(id);
      (window as unknown as { __dockCleanup?: () => void }).__dockCleanup?.();
    };
  }, [open]);

  // Nothing useful to surface yet — hide the dock entirely.
  if (!status && !isRunning && historyCount === 0) return null;

  // Dismissed + no analysis activity → minimized "다시 보기" toggle.
  if (isDismissed && !isRunning && historyCount === 0) {
    return (
      <div className="pointer-events-none fixed bottom-4 right-4 z-50 sm:bottom-6 sm:right-6">
        <button
          type="button"
          onClick={undismissStatus}
          aria-label="상태 알림 다시 보기"
          className="pointer-events-auto flex items-center gap-1.5 rounded-full border border-neutral-300 bg-white/90 px-2.5 py-1.5 text-[11px] text-neutral-600 shadow-lg shadow-black/10 backdrop-blur hover:border-neutral-400 hover:text-neutral-900 dark:border-neutral-700/60 dark:bg-surface-1/90 dark:text-neutral-400 dark:shadow-black/30 dark:hover:border-neutral-500 dark:hover:text-neutral-200"
        >
          <BellOff className="h-3.5 w-3.5" />
          <span>알림 숨김</span>
        </button>
      </div>
    );
  }

  // Pill styling is driven by the most-severe signal:
  //  ▸ system 경고 > 분석 중 > system 알림 > 정상
  // Color/icon match the priority so a glance tells the user what
  // they're looking at without having to open the popover.
  type PillTone = "warn" | "running" | "info" | "ok";
  const tone: PillTone =
    warnCount > 0 ? "warn" : isRunning ? "running" : hasIssues ? "info" : "ok";

  const toneCls: Record<PillTone, string> = {
    warn: "border-amber-500/40 bg-amber-500/15 text-amber-800 hover:bg-amber-500/25 dark:text-amber-200",
    running:
      "border-violet-500/40 bg-violet-500/15 text-violet-800 hover:bg-violet-500/25 dark:text-violet-200",
    info: "border-sky-500/40 bg-sky-500/15 text-sky-800 hover:bg-sky-500/25 dark:text-sky-200",
    ok: "border-emerald-500/30 bg-emerald-500/10 text-emerald-800 hover:bg-emerald-500/20 dark:text-emerald-200",
  };

  const dotColor: Record<PillTone, string> = {
    warn: "bg-amber-400",
    running: "bg-violet-500",
    info: "bg-sky-400",
    ok: "bg-emerald-400",
  };

  const pingColor: Record<PillTone, string> = {
    warn: "bg-amber-400",
    running: "bg-violet-400",
    info: "bg-sky-400",
    ok: "bg-emerald-400",
  };

  const PillIcon =
    tone === "warn"
      ? AlertTriangle
      : tone === "running"
        ? Sparkles
        : tone === "info"
          ? Info
          : ShieldCheck;

  const pillLabel =
    tone === "warn"
      ? "경고"
      : tone === "running"
        ? "분석 중"
        : tone === "info"
          ? "알림"
          : "정상";

  const showPing = tone === "warn" || tone === "running";

  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex flex-col items-end gap-2 sm:bottom-6 sm:right-6">
      {open && (
        <div
          ref={popoverRef}
          role="dialog"
          aria-label="활동 센터"
          className="pointer-events-auto w-[min(92vw,400px)] overflow-hidden rounded-xl border border-neutral-200 bg-white shadow-2xl shadow-black/10 dark:border-neutral-700 dark:bg-surface-1 dark:shadow-black/50"
          onPointerDown={(e) => e.stopPropagation()}
        >
          <div className="flex items-center justify-between border-b border-neutral-200 bg-neutral-50 px-4 py-2.5 dark:border-neutral-800 dark:bg-surface-2">
            <div className="flex items-center gap-2 text-sm font-semibold text-neutral-900 dark:text-neutral-100">
              <PillIcon
                className={cn(
                  "h-4 w-4",
                  tone === "warn"
                    ? "text-amber-700 dark:text-amber-300"
                    : tone === "running"
                      ? "text-violet-600 dark:text-violet-400"
                      : tone === "info"
                        ? "text-sky-700 dark:text-sky-300"
                        : "text-emerald-700 dark:text-emerald-300",
                )}
              />
              활동 센터
            </div>
            <button
              type="button"
              onClick={close}
              aria-label="닫기"
              className="rounded-full p-1 text-neutral-500 hover:bg-neutral-200 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-surface-3 dark:hover:text-neutral-100"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="max-h-[70vh] overflow-y-auto">
            {/* ── 시스템 상태 섹션 ─────────────────────────────── */}
            {status && (
              <section className="border-b border-neutral-200 dark:border-neutral-800">
                <div className="flex items-center justify-between px-4 pt-3 pb-1.5">
                  <h3 className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-neutral-700 dark:text-neutral-400">
                    {warnCount > 0 ? (
                      <AlertTriangle className="h-3 w-3 text-amber-700 dark:text-amber-300" />
                    ) : hasIssues ? (
                      <Info className="h-3 w-3 text-sky-700 dark:text-sky-300" />
                    ) : (
                      <ShieldCheck className="h-3 w-3 text-emerald-700 dark:text-emerald-300" />
                    )}
                    시스템 상태
                    {hasIssues && (
                      <span
                        className={cn(
                          "ml-1 rounded-full px-1.5 py-0.5 text-[9px] tabular-nums",
                          warnCount > 0
                            ? "bg-amber-500/20 text-amber-800 dark:text-amber-200"
                            : "bg-sky-500/20 text-sky-800 dark:text-sky-200",
                        )}
                      >
                        {warnCount > 0 ? `경고 ${warnCount}` : `알림 ${infoCount}`}
                      </span>
                    )}
                  </h3>
                  <span className="text-[10px] text-neutral-500 dark:text-neutral-500">
                    {lastSync ? `${timeAgo(lastSync)}` : "—"}
                  </span>
                </div>
                <div className="space-y-1.5 px-4 pb-3 text-xs">
                  {hasIssues ? (
                    lines.map((line, i) => (
                      <div key={i} className="flex items-start gap-2">
                        {line.level === "warn" ? (
                          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-700 dark:text-amber-300" />
                        ) : (
                          <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-sky-700 dark:text-sky-300" />
                        )}
                        <span className="leading-relaxed text-neutral-700 dark:text-neutral-300">
                          {line.message}
                        </span>
                      </div>
                    ))
                  ) : (
                    <p className="flex items-center gap-2 text-neutral-700 dark:text-neutral-400">
                      <ShieldCheck className="h-3.5 w-3.5 text-emerald-700 dark:text-emerald-300" />
                      모든 서비스가 정상 동작 중입니다.
                    </p>
                  )}
                  {hasIssues && (
                    <div className="pt-1">
                      <button
                        type="button"
                        onClick={dismissStatus}
                        className="rounded-full px-2 py-0.5 text-[11px] text-neutral-600 hover:bg-neutral-200 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-surface-3 dark:hover:text-neutral-100"
                      >
                        이 알림 숨기기
                      </button>
                    </div>
                  )}
                </div>
              </section>
            )}

            {/* ── AI 분석 섹션 ─────────────────────────────────── */}
            {(isRunning || historyCount > 0) && (
              <section>
                <div className="flex items-center justify-between px-4 pt-3 pb-1.5">
                  <h3 className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-violet-700 dark:text-violet-300">
                    <Sparkles className="h-3 w-3" />
                    AI 분석
                    {(isRunning || historyCount > 0) && (
                      <span className="ml-1 rounded-full bg-violet-500/20 px-1.5 py-0.5 text-[9px] tabular-nums text-violet-800 dark:text-violet-100">
                        {isRunning ? `진행 ${runningCount}` : `새 알림 ${historyCount}`}
                      </span>
                    )}
                  </h3>
                  <div className="flex items-center gap-2">
                    {unseenEntries.length > 0 && (
                      <button
                        type="button"
                        onClick={() => markAllAnalysisSeen(unseenEntries.map((e) => e.cveId))}
                        className="text-[10px] font-medium text-neutral-600 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100"
                        title="이 알림 목록을 모두 확인 처리"
                      >
                        모두 읽음
                      </button>
                    )}
                    <Link
                      href={"/analysis" as never}
                      onClick={() => {
                        // 전체 보기로 이동 = 사용자가 어차피 분석 탭에서 다 보게 됨
                        // → unseen 모두 확인 처리.
                        markAllAnalysisSeen(unseenEntries.map((e) => e.cveId));
                        close();
                      }}
                      className="text-[10px] font-medium text-violet-700 hover:text-violet-900 dark:text-violet-300 dark:hover:text-violet-200"
                    >
                      전체 보기 →
                    </Link>
                  </div>
                </div>
                {runningCveIds.length > 0 && (
                  <div className="px-4 pb-2">
                    <ul className="space-y-1">
                      {runningCveIds.map((cid) => (
                        <li key={cid}>
                          <Link
                            href={`/cve/${encodeURIComponent(cid)}` as never}
                            onClick={close}
                            className="flex items-center gap-2 rounded-lg px-2 py-1 text-[11px] text-neutral-900 transition-colors hover:bg-violet-50 dark:text-neutral-100 dark:hover:bg-violet-500/10"
                          >
                            <Loader2 className="h-3 w-3 animate-spin text-violet-600 dark:text-violet-400" />
                            <span className="font-mono">{cid}</span>
                            <span className="ml-auto text-[10px] text-neutral-500 dark:text-neutral-500">
                              분석 중
                            </span>
                          </Link>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {unseenEntries.length > 0 ? (
                  // unseen 항목만 노출. 카드 클릭 = navigate + "확인했음".
                  // hover 시 우측 ✕ 버튼은 navigate 없이 그 항목만 읽음 처리.
                  // 분석 기록 자체는 /analysis 탭에 그대로 유지됩니다.
                  <ul className="divide-y divide-neutral-200 px-2 pb-2 dark:divide-neutral-800">
                    {recentExcerpt.map((e) => (
                      <li
                        key={e.cveId}
                        className="group relative rounded-lg transition-colors hover:bg-neutral-50 dark:hover:bg-surface-2"
                      >
                        <Link
                          href={`/cve/${encodeURIComponent(e.cveId)}` as never}
                          onClick={() => {
                            markAnalysisSeen(e.cveId);
                            close();
                          }}
                          className="block rounded-lg px-2 py-2 pr-7"
                        >
                          <div className="flex items-baseline justify-between gap-2">
                            <span className="font-mono text-[12px] font-semibold text-neutral-900 dark:text-neutral-100">
                              {e.cveId}
                            </span>
                            <span className="shrink-0 flex items-center gap-1.5">
                              {e.status === "failed" && (
                                <span
                                  className="inline-flex items-center rounded-full bg-rose-100 px-1.5 py-px text-[10px] font-medium text-rose-700 dark:bg-rose-500/15 dark:text-rose-300"
                                  title={e.errorMessage || "분석 실패"}
                                >
                                  실패
                                </span>
                              )}
                              <span className="text-[10px] tabular-nums text-neutral-500 dark:text-neutral-500">
                                {formatAge(e.timestamp)}
                              </span>
                            </span>
                          </div>
                          <p
                            className={
                              "mt-0.5 line-clamp-2 text-[11px] leading-snug " +
                              (e.status === "failed"
                                ? "text-rose-700 dark:text-rose-300"
                                : "text-neutral-700 dark:text-neutral-400")
                            }
                          >
                            {e.status === "failed"
                              ? e.errorMessage || e.attackMethod
                              : e.attackMethod}
                          </p>
                          {e.status !== "failed" && (
                            <div className="mt-1 flex items-center gap-2 text-[10px] text-neutral-600 dark:text-neutral-500">
                              <span>페이로드 {e.payloadCount}</span>
                              <span>·</span>
                              <span>대응 {e.mitigationCount}</span>
                            </div>
                          )}
                        </Link>
                        <button
                          type="button"
                          onClick={(ev) => {
                            ev.preventDefault();
                            ev.stopPropagation();
                            markAnalysisSeen(e.cveId);
                          }}
                          title="알림에서만 숨기기 (분석 기록은 유지)"
                          aria-label="이 알림 읽음 처리"
                          className="invisible absolute right-1 top-1.5 inline-flex h-5 w-5 items-center justify-center rounded-full text-neutral-500 hover:bg-neutral-200 hover:text-neutral-900 group-hover:visible dark:hover:bg-surface-3 dark:hover:text-neutral-100"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </li>
                    ))}
                  </ul>
                ) : runningCveIds.length === 0 ? (
                  <p className="px-4 pb-3 text-[11px] text-neutral-600 dark:text-neutral-500">
                    {entries.length === 0
                      ? "아직 실행한 AI 분석이 없습니다."
                      : "새로 도착한 분석 알림이 없어요. 전체 기록은 /analysis 탭에서 확인할 수 있습니다."}
                  </p>
                ) : null}
                {/* 활동 센터에서는 분석 기록 일괄 삭제를 노출하지 않습니다.
                    "알림 숨기기" 와 헷갈려 분석 기록까지 한꺼번에 지우는
                    실수가 있었어요. 일괄 삭제는 /analysis 페이지에서. */}
              </section>
            )}
          </div>
        </div>
      )}

      {/* Single pill — combines status indicator + optional analysis chip.
          Status dot/icon on the left tells the user what tone the system
          is in; the analysis chip on the right is the at-a-glance count
          of in-flight or completed analyses. One click opens everything. */}
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "pointer-events-auto flex items-center gap-2 rounded-full border px-3.5 py-2 text-xs font-medium shadow-lg shadow-black/10 backdrop-blur transition-colors active:scale-95 dark:shadow-black/30",
          toneCls[tone],
        )}
        aria-expanded={open}
        aria-haspopup="dialog"
        aria-label="활동 센터 열기"
      >
        <span className="relative flex h-2 w-2">
          {showPing && (
            <span
              className={cn(
                "absolute inline-flex h-full w-full animate-ping rounded-full opacity-60",
                pingColor[tone],
              )}
            />
          )}
          <span className={cn("relative inline-flex h-2 w-2 rounded-full", dotColor[tone])} />
        </span>
        {tone === "running" ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <PillIcon className="h-4 w-4" />
        )}
        <span>{pillLabel}</span>
        {hasIssues && tone !== "running" && (
          <span
            className={cn(
              "rounded-full px-1.5 py-0.5 text-[10px] font-semibold tabular-nums",
              warnCount > 0
                ? "bg-amber-500/25 text-amber-800 dark:text-amber-200"
                : "bg-sky-500/25 text-sky-800 dark:text-sky-200",
            )}
          >
            {warnCount > 0 ? warnCount : infoCount}
          </span>
        )}
        {(isRunning || historyCount > 0) && tone !== "running" && (
          <span
            className="flex items-center gap-1 rounded-full bg-violet-500/25 px-1.5 py-0.5 text-[10px] font-semibold tabular-nums text-violet-800 dark:bg-violet-500/30 dark:text-violet-100"
            title={isRunning ? "분석 진행 중" : "최근 분석 기록"}
          >
            {isRunning ? (
              <Loader2 className="h-2.5 w-2.5 animate-spin" />
            ) : (
              <Sparkles className="h-2.5 w-2.5" />
            )}
            {isRunning ? runningCount : historyCount}
          </span>
        )}
        {tone === "running" && historyCount > 0 && (
          <span
            className="rounded-full bg-violet-500/30 px-1.5 py-0.5 text-[10px] font-semibold tabular-nums text-violet-100 dark:bg-violet-500/40"
            title={`진행 ${runningCount} · 기록 ${historyCount}`}
          >
            {runningCount}
          </span>
        )}
      </button>
    </div>
  );
}
