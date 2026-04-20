"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, BellOff, Info, ShieldCheck, X } from "lucide-react";
import { useStatus } from "@/hooks/useStatus";
import type { IngestionSnapshot, Source, StatusReport } from "@/lib/types";
import { useUserSetting } from "@/lib/user-settings";
import { cn, timeAgo } from "@/lib/utils";

const SOURCE_LABEL: Record<Source, string> = {
  nvd: "NVD",
  exploit_db: "Exploit-DB",
  github_advisory: "GitHub Advisory",
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

  // 서버 env나 사용자 localStorage 중 하나라도 있으면 키 있는 것으로 간주 —
  // /admin/refresh 호출 시 클라이언트 키를 헤더로 전달하므로 실제 수집에 사용됨.
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

export function StatusBanner() {
  const { data } = useStatus();
  const { value: nvdApiKey } = useUserSetting("nvdApiKey");
  const { value: githubToken } = useUserSetting("githubToken");
  const [open, setOpen] = useState(false);
  const [dismissedSig, setDismissedSig] = useState<string | null>(null);
  const popoverRef = useRef<HTMLDivElement | null>(null);
  const buttonRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    setDismissedSig(readDismissed());
  }, []);

  const clientKeys = useMemo(
    () => ({ nvd: !!nvdApiKey, github: !!githubToken }),
    [nvdApiKey, githubToken],
  );
  const lines = useMemo(() => buildLines(data, clientKeys), [data, clientKeys]);
  const sig = useMemo(() => signature(lines), [lines]);
  const warnCount = lines.filter((l) => l.level === "warn").length;
  const infoCount = lines.filter((l) => l.level === "info").length;
  const hasIssues = lines.length > 0;
  const isDismissed = dismissedSig !== null && dismissedSig === sig;

  const lastSync = useMemo(() => {
    if (!data) return null;
    const stamps = data.ingestions
      .map((i) => i.finishedAt)
      .filter((t): t is string => !!t)
      .sort();
    return stamps.length ? stamps[stamps.length - 1] : null;
  }, [data]);

  const close = useCallback(() => setOpen(false), []);

  const dismiss = useCallback(() => {
    writeDismissed(sig);
    setDismissedSig(sig);
    setOpen(false);
  }, [sig]);

  const undismiss = useCallback(() => {
    writeDismissed(null);
    setDismissedSig(null);
  }, []);

  useEffect(() => {
    if (!open) return;
    // Attach on next tick so the click that opened us isn't captured as
    // outside-click on the same turn.
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
      (window as unknown as { __sbCleanup?: () => void }).__sbCleanup = () => {
        document.removeEventListener("pointerdown", onDown, true);
        document.removeEventListener("keydown", onKey);
      };
    }, 0);
    return () => {
      window.clearTimeout(id);
      (window as unknown as { __sbCleanup?: () => void }).__sbCleanup?.();
    };
  }, [open]);

  if (!data) return null;

  const Icon = warnCount > 0 ? AlertTriangle : hasIssues ? Info : ShieldCheck;
  const iconTint =
    warnCount > 0 ? "text-amber-300" : hasIssues ? "text-sky-300" : "text-emerald-300";
  const label = warnCount > 0 ? `경고 ${warnCount}` : hasIssues ? `알림 ${infoCount}` : "정상";

  // 사용자가 명시적으로 꺼놓은 상태면 '다시 보기' 미니 토글만 노출.
  if (isDismissed && !open) {
    return (
      <div className="pointer-events-none fixed bottom-4 right-4 z-50 sm:bottom-6 sm:right-6">
        <button
          type="button"
          onClick={undismiss}
          aria-label="상태 알림 다시 보기"
          className="pointer-events-auto flex items-center gap-1.5 rounded-full border border-neutral-700/60 bg-surface-1/90 px-2.5 py-1.5 text-[11px] text-neutral-400 shadow-lg shadow-black/30 backdrop-blur hover:border-neutral-500 hover:text-neutral-200"
        >
          <BellOff className="h-3.5 w-3.5" />
          <span>알림 숨김</span>
        </button>
      </div>
    );
  }

  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex flex-col items-end gap-2 sm:bottom-6 sm:right-6">
      {open && (
        <div
          ref={popoverRef}
          role="dialog"
          aria-label="시스템 상태 상세"
          className="pointer-events-auto w-[min(92vw,380px)] overflow-hidden rounded-lg border border-neutral-700 bg-surface-1 shadow-2xl shadow-black/50"
          onPointerDown={(e) => e.stopPropagation()}
        >
          <div className="flex items-center justify-between border-b border-neutral-800 bg-surface-2 px-4 py-2.5">
            <div className="flex items-center gap-2 text-sm font-semibold text-neutral-100">
              <Icon className={cn("h-4 w-4", iconTint)} />
              시스템 상태
            </div>
            <button
              type="button"
              onClick={close}
              aria-label="닫기"
              className="rounded p-1 text-neutral-400 hover:bg-surface-3 hover:text-neutral-100"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="max-h-[60vh] space-y-2 overflow-y-auto px-4 py-3 text-xs">
            {hasIssues ? (
              lines.map((line, i) => (
                <div key={i} className="flex items-start gap-2">
                  {line.level === "warn" ? (
                    <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-300" />
                  ) : (
                    <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-sky-300" />
                  )}
                  <span className="leading-relaxed text-neutral-300">{line.message}</span>
                </div>
              ))
            ) : (
              <p className="flex items-center gap-2 text-neutral-400">
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-300" />
                모든 서비스가 정상 동작 중입니다.
              </p>
            )}
          </div>
          <div className="flex items-center justify-between gap-2 border-t border-neutral-800 bg-surface-0 px-4 py-2 text-[11px] text-neutral-500">
            <span>
              {lastSync ? `마지막 수집 ${timeAgo(lastSync)}` : "수집 기록 없음"}
            </span>
            {hasIssues && (
              <button
                type="button"
                onClick={dismiss}
                className="rounded px-2 py-0.5 text-neutral-400 hover:bg-surface-3 hover:text-neutral-100"
              >
                이 알림 숨기기
              </button>
            )}
          </div>
        </div>
      )}

      <button
        ref={buttonRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "pointer-events-auto flex items-center gap-2 rounded-full border px-3.5 py-2 text-xs font-medium shadow-lg shadow-black/30 backdrop-blur transition-colors",
          warnCount > 0
            ? "border-amber-500/40 bg-amber-500/15 text-amber-300 hover:bg-amber-500/25"
            : hasIssues
              ? "border-sky-500/40 bg-sky-500/15 text-sky-300 hover:bg-sky-500/25"
              : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20",
        )}
        aria-expanded={open}
        aria-haspopup="dialog"
      >
        <span className="relative flex h-2 w-2">
          {warnCount > 0 && (
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber-400 opacity-60" />
          )}
          <span
            className={cn(
              "relative inline-flex h-2 w-2 rounded-full",
              warnCount > 0 ? "bg-amber-400" : hasIssues ? "bg-sky-400" : "bg-emerald-400",
            )}
          />
        </span>
        <Icon className={cn("h-4 w-4", iconTint)} />
        <span>{hasIssues ? "경고 보기" : "상태 보기"}</span>
        <span className="rounded-full bg-black/30 px-1.5 py-0.5 text-[10px] text-neutral-100">
          {label}
        </span>
      </button>
    </div>
  );
}
