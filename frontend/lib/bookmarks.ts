"use client";

import { useCallback, useEffect, useState } from "react";

import { ApiError, api } from "./api";
import { useAuth } from "./auth-context";

const CACHE_KEY = "kestrel:bookmarks";
const SYNC_EVENT = "kestrel:bookmarks";

function readCache(): Set<string> {
  if (typeof window === "undefined") return new Set();
  try {
    const raw = window.localStorage.getItem(CACHE_KEY);
    return new Set(raw ? (JSON.parse(raw) as string[]) : []);
  } catch {
    return new Set();
  }
}

function writeCache(set: Set<string>) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(CACHE_KEY, JSON.stringify([...set]));
  } catch {
    /* ignore quota */
  }
  window.dispatchEvent(new Event(SYNC_EVENT));
}

export function useBookmarks() {
  const { user, loading: authLoading } = useAuth();
  const [set, setSet] = useState<Set<string>>(() => new Set());
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (authLoading) return;
    let cancelled = false;
    if (!user) {
      // 비로그인 — 캐시 비우고 ready. 토글은 /login 으로 가드.
      writeCache(new Set());
      setSet(new Set());
      setReady(true);
      return;
    }
    const cached = readCache();
    setSet(cached);
    api
      .getBookmarks()
      .then((res) => {
        if (cancelled) return;
        const next = new Set(res.items.map((b) => b.cveId));
        writeCache(next);
        setSet(next);
      })
      .catch((err) => {
        // 401 이면 세션 만료 — 캐시 비우고 비로그인 상태로.
        if (err instanceof ApiError && err.status === 401) {
          writeCache(new Set());
          setSet(new Set());
        }
      })
      .finally(() => {
        if (!cancelled) setReady(true);
      });

    const sync = () => setSet(readCache());
    window.addEventListener(SYNC_EVENT, sync);
    window.addEventListener("storage", sync);
    return () => {
      cancelled = true;
      window.removeEventListener(SYNC_EVENT, sync);
      window.removeEventListener("storage", sync);
    };
  }, [user, authLoading]);

  const toggle = useCallback(
    (cveId: string) => {
      // 비로그인 상태에서 즐겨찾기 토글 시도 → 로그인 페이지로.
      if (!user) {
        if (typeof window !== "undefined") {
          const next = window.location.pathname + window.location.search;
          window.location.href = `/login?next=${encodeURIComponent(next)}`;
        }
        return;
      }
      const current = readCache();
      const wasOn = current.has(cveId);
      const next = new Set(current);
      if (wasOn) next.delete(cveId);
      else next.add(cveId);
      writeCache(next);
      setSet(next);

      const op = wasOn ? api.removeBookmark(cveId) : api.addBookmark(cveId);
      op.catch(() => {
        const reverted = new Set(readCache());
        if (wasOn) reverted.add(cveId);
        else reverted.delete(cveId);
        writeCache(reverted);
        setSet(reverted);
      });
    },
    [user],
  );

  const has = useCallback((cveId: string) => set.has(cveId), [set]);

  return { set, has, toggle, ready, count: set.size };
}
