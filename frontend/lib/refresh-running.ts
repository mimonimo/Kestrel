// "지금 동기화" 클릭 후 RefreshBar 가 마운트된 상태 (메인 페이지) 가
// 아니어도 진행 상태를 잃지 않도록 localStorage 에 영속. ingestion
// 완료는 useStatus 의 lastSync timestamp 가 startedAt 보다 늦어지는
// 시점으로 감지합니다 (10분 stale fallback).

import { useEffect, useState } from "react";

const KEY = "kestrel:refresh-running";
const STALE_MS = 10 * 60 * 1000;

export interface RunningRefresh {
  startedAt: number;
}

function read(): RunningRefresh | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as RunningRefresh;
    if (!parsed || typeof parsed.startedAt !== "number") return null;
    if (Date.now() - parsed.startedAt > STALE_MS) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function readRefreshRunning(): RunningRefresh | null {
  return read();
}

export function markRefreshRunning(): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(KEY, JSON.stringify({ startedAt: Date.now() }));
    window.dispatchEvent(new Event("kestrel:refresh-running-changed"));
  } catch {
    /* quota */
  }
}

export function clearRefreshRunning(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(KEY);
  window.dispatchEvent(new Event("kestrel:refresh-running-changed"));
}

export function useRefreshRunning(): RunningRefresh | null {
  const [r, setR] = useState<RunningRefresh | null>(null);
  useEffect(() => {
    const sync = () => setR(read());
    sync();
    window.addEventListener("kestrel:refresh-running-changed", sync);
    window.addEventListener("storage", sync);
    // STALE_MS 자동 정리 — 페이지 오래 머물러도 늙은 마커가 살아남지 않게.
    const interval = window.setInterval(sync, 30_000);
    return () => {
      window.removeEventListener("kestrel:refresh-running-changed", sync);
      window.removeEventListener("storage", sync);
      window.clearInterval(interval);
    };
  }, []);
  return r;
}
