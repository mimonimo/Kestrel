"use client";

import Link from "next/link";
import { Bell } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { useAssets } from "@/lib/assets";
import { cn } from "@/lib/utils";
import { timeAgo } from "@/lib/utils";

const SEEN_KEY = "kestrel:notif:lastSeenAt";

function readSeen(): number {
  if (typeof window === "undefined") return 0;
  const raw = window.localStorage.getItem(SEEN_KEY);
  if (!raw) return 0;
  const t = Date.parse(raw);
  return Number.isFinite(t) ? t : 0;
}

function writeSeen(iso: string) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(SEEN_KEY, iso);
  window.dispatchEvent(new Event("kestrel:notif-seen"));
}

const SEV_DOT: Record<string, string> = {
  critical: "bg-rose-400",
  high: "bg-orange-400",
  medium: "bg-amber-400",
  low: "bg-sky-400",
};

export function NotificationBell() {
  const { list: assets, ready } = useAssets();
  const [open, setOpen] = useState(false);
  const [lastSeen, setLastSeen] = useState<number>(0);
  const popoverRef = useRef<HTMLDivElement | null>(null);
  const buttonRef = useRef<HTMLButtonElement | null>(null);

  // Hydrate lastSeenAt + listen for cross-tab updates.
  useEffect(() => {
    setLastSeen(readSeen());
    const sync = () => setLastSeen(readSeen());
    window.addEventListener("kestrel:notif-seen", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("kestrel:notif-seen", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  // Click-outside close.
  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      const t = e.target as Node;
      if (popoverRef.current?.contains(t) || buttonRef.current?.contains(t)) return;
      setOpen(false);
    };
    window.addEventListener("mousedown", onClick);
    return () => window.removeEventListener("mousedown", onClick);
  }, [open]);

  // Only fetch when there are assets to match against. Refetch every
  // 5 min in the background so the bell stays current without making the
  // header itself a query trigger on every nav.
  const q = useQuery({
    queryKey: ["asset-notifications", assets.map((a) => a.id).join(",")],
    queryFn: () => api.getAssetNotifications(assets, 14, 50),
    enabled: ready && assets.length > 0,
    staleTime: 60_000,
    refetchInterval: 5 * 60_000,
  });

  const items = q.data?.items ?? [];

  const unreadCount = useMemo(() => {
    if (!items.length) return 0;
    if (lastSeen === 0) return items.length;  // never read → all unread
    return items.filter((it) => {
      const t = it.publishedAt ? Date.parse(it.publishedAt) : 0;
      return t > lastSeen;
    }).length;
  }, [items, lastSeen]);

  const markAllRead = () => {
    writeSeen(new Date().toISOString());
  };

  // Always render the button (even with 0 assets) so the user knows the
  // surface exists; the popover then guides them to /settings to add
  // assets. Without this the missing bell looks like a broken layout.
  return (
    <div className="relative">
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-label={`알림 ${unreadCount > 0 ? `(${unreadCount}개 읽지 않음)` : ""}`}
        className="relative flex h-8 w-8 items-center justify-center rounded-full text-neutral-600 transition-colors hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-surface-2 dark:hover:text-neutral-100"
      >
        <Bell className="h-4 w-4" />
        {unreadCount > 0 && (
          <span className="absolute -right-1 -top-1 inline-flex min-w-[1.1rem] items-center justify-center rounded-full bg-rose-500 px-1 text-[10px] font-semibold leading-4 text-white ring-2 ring-white dark:ring-surface-0">
            {unreadCount > 99 ? "99+" : unreadCount}
          </span>
        )}
      </button>
      {open && (
        <div
          ref={popoverRef}
          // 모바일: 종 버튼 기준 right-0 으로 두면 92vw 너비가 화면 왼쪽으로
          // 넘쳐 잘리던 문제 → viewport 기준 fixed(헤더 h-14 아래, 좌우 여백).
          // sm+ 에선 기존처럼 종 버튼에 붙는 absolute 드롭다운.
          className="fixed left-3 right-3 top-14 z-50 overflow-hidden rounded-xl border border-neutral-200 bg-white shadow-lg sm:absolute sm:left-auto sm:right-0 sm:top-full sm:mt-1.5 sm:w-[min(92vw,22rem)] dark:border-neutral-800 dark:bg-surface-1"
        >
          <div className="flex items-center justify-between gap-2 border-b border-neutral-200 px-3 py-2 dark:border-neutral-800">
            <span className="text-xs font-semibold text-neutral-800 dark:text-neutral-200">
              자산 매칭 알림 (최근 14일)
            </span>
            {items.length > 0 && (
              <button
                type="button"
                onClick={markAllRead}
                className="text-[11px] text-neutral-600 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-100"
              >
                모두 읽음
              </button>
            )}
          </div>
          <div className="max-h-80 overflow-y-auto">
            {!ready ? (
              <p className="px-3 py-4 text-xs text-neutral-600 dark:text-neutral-500">로딩…</p>
            ) : assets.length === 0 ? (
              <div className="px-3 py-4 text-xs text-neutral-700 dark:text-neutral-400">
                등록된 자산이 없습니다.{" "}
                <Link
                  href="/settings"
                  className="text-sky-700 underline hover:text-sky-800 dark:text-sky-300 dark:hover:text-sky-200"
                  onClick={() => setOpen(false)}
                >
                  설정 → 내 자산
                </Link>{" "}
                에서 vendor/product 를 등록하면 새 CVE 가 여기에 표시됩니다.
              </div>
            ) : q.isLoading ? (
              <p className="px-3 py-4 text-xs text-neutral-600 dark:text-neutral-500">조회 중…</p>
            ) : q.error ? (
              <p className="px-3 py-4 text-xs text-rose-700 dark:text-rose-300">
                조회 실패: {(q.error as Error).message}
              </p>
            ) : items.length === 0 ? (
              <p className="px-3 py-4 text-xs text-neutral-600 dark:text-neutral-500">
                최근 14일 내 자산 매칭 CVE 가 없습니다.
              </p>
            ) : (
              <ul className="divide-y divide-neutral-200 dark:divide-neutral-800">
                {items.map((it) => {
                  const t = it.publishedAt ? Date.parse(it.publishedAt) : 0;
                  const isUnread = t > lastSeen;
                  return (
                    <li key={it.cveId}>
                      <Link
                        href={`/cve/${encodeURIComponent(it.cveId)}` as never}
                        className={cn(
                          "flex items-start gap-2 px-3 py-2 hover:bg-neutral-50 dark:hover:bg-surface-2",
                          isUnread && "bg-rose-500/5",
                        )}
                        onClick={() => setOpen(false)}
                      >
                        <span
                          className={cn(
                            "mt-1.5 h-2 w-2 shrink-0 rounded-full",
                            it.severity ? SEV_DOT[it.severity] ?? "bg-neutral-500" : "bg-neutral-400 dark:bg-neutral-600",
                          )}
                          title={it.severity ?? "unknown severity"}
                        />
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-mono text-[11px] text-neutral-600 dark:text-neutral-400">
                              {it.cveId}
                            </span>
                            {it.publishedAt && (
                              <span className="text-[10px] tabular-nums text-neutral-500 dark:text-neutral-500">
                                {timeAgo(it.publishedAt)}
                              </span>
                            )}
                          </div>
                          <p
                            className={cn(
                              "mt-0.5 line-clamp-2 text-xs leading-snug",
                              isUnread
                                ? "text-neutral-900 dark:text-neutral-100"
                                : "text-neutral-600 dark:text-neutral-400",
                            )}
                          >
                            {it.title}
                          </p>
                        </div>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
